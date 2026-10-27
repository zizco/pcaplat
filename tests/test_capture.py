"""Host checks and capture helpers, tested on recorded tool outputs."""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

import pytest

from builders import ipv4, udp, write_pcap
from pcaplat import capture
from pcaplat.cli import main

ETHTOOL_HW_NEW = """Time stamping parameters for enp1s0f0:
Capabilities:
\thardware-transmit
\tsoftware-transmit
\thardware-receive
\tsoftware-receive
\tsoftware-system-clock
\thardware-raw-clock
PTP Hardware Clock: 2
Hardware Transmit Timestamp Modes:
\toff
\ton
Hardware Receive Filter Modes:
\tnone
\tall
"""

ETHTOOL_HW_OLD = """Time stamping parameters for eth2:
Capabilities:
\thardware-transmit     (SOF_TIMESTAMPING_TX_HARDWARE)
\tsoftware-transmit     (SOF_TIMESTAMPING_TX_SOFTWARE)
\thardware-receive      (SOF_TIMESTAMPING_RX_HARDWARE)
\tsoftware-receive      (SOF_TIMESTAMPING_RX_SOFTWARE)
\tsoftware-system-clock (SOF_TIMESTAMPING_SOFTWARE)
\thardware-raw-clock    (SOF_TIMESTAMPING_RAW_HARDWARE)
PTP Hardware Clock: 0
Hardware Transmit Timestamp Modes:
\toff                   (HWTSTAMP_TX_OFF)
\ton                    (HWTSTAMP_TX_ON)
Hardware Receive Filter Modes:
\tnone                  (HWTSTAMP_FILTER_NONE)
\tptpv2-event           (HWTSTAMP_FILTER_PTP_V2_EVENT)
"""

ETHTOOL_SW = """Time stamping parameters for lo:
Capabilities:
\tsoftware-transmit
\tsoftware-receive
\tsoftware-system-clock
PTP Hardware Clock: none
Hardware Transmit Timestamp Modes: none
Hardware Receive Filter Modes: none
"""

TCPDUMP_J_HW = """Time stamp types for enp1s0f0 (use option -j to set):
  host (Host)
  adapter_unsynced (Adapter, not synced with system time)
"""
TCPDUMP_J_SW = """Time stamp types for lo (use option -j to set):
  host (Host)
"""
TCPDUMP_STATS = """tcpdump: listening on enp1s0f0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
^C1203411 packets captured
1203790 packets received by filter
379 packets dropped by kernel
12 packets dropped by interface
"""
PMC = """sending: GET CURRENT_DATA_SET
\t90e2ba.fffe.6d4c1a-1 seq 0 RESPONSE MANAGEMENT CURRENT_DATA_SET
\t\tstepsRemoved     1
\t\toffsetFromMaster -7.0
\t\tmeanPathDelay    642.0
"""


# ---------------------------------------------------------------- parsers
def test_ethtool_new_format_with_hardware():
    e = capture.parse_ethtool_ts(ETHTOOL_HW_NEW)
    assert e["hw_receive"] and e["hw_raw_clock"] and e["phc"] == 2 and e["rx_filter_all"]


def test_ethtool_old_format_with_ptp_only_filter():
    e = capture.parse_ethtool_ts(ETHTOOL_HW_OLD)
    assert e["hw_receive"] and e["phc"] == 0
    assert not e["rx_filter_all"] and e["rx_filters"] == ["ptpv2-event"]


def test_ethtool_software_only():
    e = capture.parse_ethtool_ts(ETHTOOL_SW)
    assert not e["hw_receive"] and e["phc"] is None and e["rx_filters"] == []


def test_tcpdump_timestamp_types():
    assert capture.parse_tstamp_types(TCPDUMP_J_HW) == ["host", "adapter_unsynced"]
    assert capture.parse_tstamp_types(TCPDUMP_J_SW) == ["host"]


def test_tcpdump_statistics():
    assert capture.parse_tcpdump_stats(TCPDUMP_STATS) == {
        "captured": 1203411, "received_by_filter": 1203790, "dropped_by_kernel": 379, "dropped_by_interface": 12}


def test_pmc_offset_and_coalescing():
    assert capture.parse_pmc_offset(PMC) == -7.0
    assert capture.parse_pmc_offset("sending: GET CURRENT_DATA_SET\n") is None
    assert capture.parse_rx_usecs("Coalesce parameters for eth1:\nrx-usecs: 50\nrx-frames: 0\n") == 50


# ---------------------------------------------------------------- choices
def test_timestamp_choice():
    assert capture.choose_tstamp("auto", ["host", "adapter_unsynced"]) == ("adapter_unsynced", None)
    t, warn = capture.choose_tstamp("auto", ["host"])
    assert t == "host" and "falling back" in warn
    assert capture.choose_tstamp("host", ["host", "adapter_unsynced"]) == ("host", None)
    with pytest.raises(RuntimeError):
        capture.choose_tstamp("hardware", ["host"])


def test_tcpdump_command():
    cmd = capture.build_command("eth1", "a.pcap", "adapter_unsynced", bpf="udp and dst port 31001", as_root=True)
    assert cmd[:3] == ["tcpdump", "-i", "eth1"] and "--time-stamp-precision=nano" in cmd
    assert cmd[cmd.index("-j") + 1] == "adapter_unsynced" and cmd[-1] == "udp and dst port 31001"
    assert cmd[cmd.index("-B") + 1] == str(256 * 1024)
    assert "-j" not in capture.build_command("lo", "a.pcap", "host")


def _ptp(sync=True, worst=7.0, reason=None):
    return {"ptp4l_running": True, "phc2sys_running": False, "phc": 2, "port": "eth1", "port_state": "SLAVE",
            "port_timestamping": "HARDWARE", "gm_present": True,
            "offsets_ns": [-worst, 3.0, 5.0] if sync else [], "max_abs_offset_ns": worst if sync else None,
            "synchronized": sync, "reason": reason}


def _info(hw=True, ptp=None, rx_usecs=None):
    return {"interface": "eth1", "root": True, "tcpdump": "tcpdump version 4.99.4",
            "tstamp_types": ["host", "adapter_unsynced"] if hw else ["host"], "tstamp_types_error": None,
            "ethtool": capture.parse_ethtool_ts(ETHTOOL_HW_NEW if hw else ETHTOOL_SW),
            "rx_usecs": rx_usecs, "ptp": _ptp() if ptp is None else ptp}


def test_doctor_verdicts():
    good = capture.diagnose(_info())
    assert not any(level in ("WARN", "FAIL") for level, _ in good)
    assert any("Sub-microsecond work is possible" in m and "asymmetry" in m for _, m in good)
    assert any("up to 7 ns over 3 samples" in m for _, m in good)
    unverified = capture.diagnose(_info(ptp=_ptp(sync=None, reason="no ptp4l process on this host")))
    assert any(level == "WARN" and "not verified" in m for level, m in unverified)
    assert not any("Sub-microsecond" in m for _, m in unverified)
    soft = capture.diagnose(_info(hw=False, rx_usecs=50))
    assert any(level == "WARN" and "rx-usecs = 50" in m for level, m in soft)
    assert any("millisecond-scale" in m for _, m in soft)


@pytest.mark.parametrize("ptp", [
    {"ptp4l_running": True, "phc2sys_running": False, "offset_from_master_ns": None},       # running, nothing else
    {"ptp4l_running": True, "phc2sys_running": False, "offset_from_master_ns": 5e9},        # a 5 s offset
    _ptp(sync=True, worst=5e9),
    _ptp(sync=False, reason="ptp4l port on eth1 is in state LISTENING, not SLAVE"),
], ids=["running-only", "old-style-5s", "synchronized-5s", "listening"])
def test_doctor_never_claims_sub_microsecond_without_evidence(ptp):
    lines = capture.diagnose(_info(ptp=ptp))
    assert not any("Sub-microsecond work is possible" in m for _, m in lines)
    assert any(level == "WARN" for level, _ in lines)


def _fake_tools(ports_out, phc_of, gm="true", offsets=(-7.0, 3.0, 5.0)):
    """A run() stand-in answering pmc and ethtool like a host would."""
    seq = iter(offsets)

    def fake(cmd, timeout=10.0):
        if cmd[0] == "pmc" and cmd[-1] == "GET PORT_PROPERTIES_NP":
            return 0, ports_out
        if cmd[0] == "pmc" and cmd[-1] == "GET TIME_STATUS_NP":
            if gm is None:                               # no answer: the query timed out
                return 124, "sending: GET TIME_STATUS_NP\n"
            return 0, f"\t\tgmPresent                  {gm}\n"
        if cmd[0] == "pmc" and cmd[-1] == "GET CURRENT_DATA_SET":
            return 0, f"\t\toffsetFromMaster {next(seq, 4.0)}\n"
        if cmd[:2] == ["ethtool", "-T"]:
            phc = phc_of.get(cmd[2])
            return 0, f"PTP Hardware Clock: {phc if phc is not None else 'none'}\n"
        return 127, ""
    return fake


def _ports(*items):
    return "".join(f"\t\tportIdentity            x-{i}\n\t\tportState               {st}\n"
                   f"\t\ttimestamping            {ts}\n\t\tinterface               {itf}\n"
                   for i, (st, ts, itf) in enumerate(items, 1))


@pytest.mark.parametrize("ports,phc_of,gm,expect,reason", [
    (_ports(("SLAVE", "HARDWARE", "eth1")), {"eth1": 2}, "true", True, None),
    (_ports(("SLAVE", "HARDWARE", "eth3")), {"eth3": 5}, "true", False, "does not use /dev/ptp2"),
    (_ports(("LISTENING", "HARDWARE", "eth1")), {"eth1": 2}, "true", False, "LISTENING"),
    (_ports(("SLAVE", "SOFTWARE", "eth1")), {"eth1": 2}, "true", False, "SOFTWARE timestamping"),
    (_ports(("SLAVE", "HARDWARE", "eth1")), {"eth1": 2}, "false", False, "no grandmaster"),
    ("", {}, "true", None, "did not answer"),
    (_ports(("SLAVE", "HARDWARE", "eth1")), {"eth1": 2}, None, None, "did not report whether a grandmaster"),
    (_ports(("MASTER", "HARDWARE", "eth1"), ("SLAVE", "HARDWARE", "eth2")), {"eth1": 2, "eth2": 2}, "true", True, None),
    (_ports(("SLAVE", "HARDWARE", "eth2"), ("MASTER", "HARDWARE", "eth1")), {"eth1": 2, "eth2": 2}, "true", True, None),
    (_ports(("MASTER", "HARDWARE", "eth1"), ("MASTER", "HARDWARE", "eth2")), {"eth1": 2, "eth2": 2}, "true", False,
     "no ptp4l port on /dev/ptp2 is SLAVE"),
], ids=["synchronized", "other-clock", "listening", "software", "no-grandmaster", "no-answer",
        "grandmaster-query-timeout", "boundary-master-first", "boundary-slave-first", "all-master"])
def test_ptp_status_checks_this_nic_clock(monkeypatch, ports, phc_of, gm, expect, reason):
    monkeypatch.setattr(capture, "_running", lambda name: name == "ptp4l")
    monkeypatch.setattr(capture.shutil, "which", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr(capture, "run", _fake_tools(ports, phc_of, gm))
    st = capture.ptp_status(2, samples=3, interval_s=0)
    assert st["synchronized"] is expect
    if reason:
        assert reason in st["reason"]
    else:
        assert st["offsets_ns"] == [-7.0, 3.0, 5.0] and st["max_abs_offset_ns"] == 7.0
        assert st["port_state"] == "SLAVE" and st["port"] in ("eth1", "eth2")
    if expect is not True:
        assert not any("Sub-microsecond work is possible" in m
                       for _, m in capture.diagnose(_info(ptp=st)))


def test_ptp_status_without_evidence_is_unknown(monkeypatch):
    monkeypatch.setattr(capture, "_running", lambda name: False)
    assert capture.ptp_status(2)["synchronized"] is None
    assert capture.ptp_status(None)["synchronized"] is None


def test_doctor_without_tcpdump_fails():
    info = _info()
    info["tcpdump"] = None
    level, message = capture.diagnose(info)[0]
    assert level == "FAIL" and "not installed" in message


# ---------------------------------------------------------------- metadata in reports
def _sidecar(path, tstamp="adapter_unsynced", dropped=0, ptp=True, status="complete"):
    meta = {capture.SIDECAR_MARK: 1, "file": os.path.basename(path), "host": "h", "interface": "eth1",
            "timestamp_type": tstamp,
            "timestamp_source": "NIC hardware clock (/dev/ptp2) on h:eth1" if tstamp != "host"
            else "host software clock (kernel) on h:eth1",
            "tcpdump_stats": {"captured": 10, "dropped_by_kernel": dropped},
            "ptp": _ptp() if ptp else _ptp(sync=None, reason="no ptp4l process on this host"),
            "rx_usecs": None, "status": status, "exit_code": 0 if status == "complete" else 1,
            "stderr_tail": "" if status == "complete" else "tcpdump: write: No space left on device"}
    with open(capture.sidecar_path(path), "w") as f:
        json.dump(meta, f)


def _pair(tmp_path):
    a = [(i * 1000, ipv4(udp(bytes([i])))) for i in range(20)]
    write_pcap(tmp_path / "a.pcap", a)
    write_pcap(tmp_path / "b.pcap", [(t + 300, f) for t, f in a])
    return str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap")


def test_latency_report_uses_capture_metadata(tmp_path):
    a, b = _pair(tmp_path)
    _sidecar(a, dropped=379)
    _sidecar(b)
    out = tmp_path / "rep"
    assert main(["latency", a, b, "--out", str(out)]) == 0
    md = (out / "report.md").read_text()
    assert "NIC hardware clock (/dev/ptp2) on h:eth1" in md
    assert "dropped 379 packets in the capture path" in md
    assert "A: PTP verified, offset samples up to 7 ns" in md


def test_failed_capture_is_flagged_in_the_report(tmp_path):
    a, b = _pair(tmp_path)
    _sidecar(a, status="failed")
    _sidecar(b)
    out = tmp_path / "rep"
    assert main(["latency", a, b, "--out", str(out)]) == 0
    md = (out / "report.md").read_text()
    assert "capture A did not complete normally (status failed, tcpdump exit code 1)" in md
    assert "No space left on device" in md


def test_unverified_clock_is_flagged_in_the_report(tmp_path):
    a, b = _pair(tmp_path)
    _sidecar(a, ptp=False)
    _sidecar(b)
    out = tmp_path / "rep"
    assert main(["latency", a, b, "--out", str(out)]) == 0
    assert "not verified: no ptp4l process on this host" in (out / "report.md").read_text()


def test_mismatched_timestamp_types_are_flagged(tmp_path):
    a, b = _pair(tmp_path)
    _sidecar(a, tstamp="adapter_unsynced")
    _sidecar(b, tstamp="host", ptp=False)
    out = tmp_path / "rep"
    assert main(["latency", a, b, "--out", str(out)]) == 0
    assert "37 s" in (out / "report.md").read_text()


def test_unrelated_json_next_to_a_capture_is_ignored(tmp_path):
    a, b = _pair(tmp_path)
    with open(capture.sidecar_path(a), "w") as f:
        json.dump({"something": "else"}, f)
    assert capture.load_sidecar(a) is None
    assert main(["latency", a, b, "--out", str(tmp_path / "rep")]) == 0


# ---------------------------------------------------------------- subprocess handling
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_timeout_keeps_partial_output(stream):
    code = f"import sys, time; print('partial', file=sys.{stream}, flush=True); time.sleep(5)"
    assert capture.run([sys.executable, "-c", code], timeout=0.5) == (124, "partial\n")


def _fake_tcpdump(tmp_path, body):
    child = tmp_path / "fake_tcpdump.py"
    child.write_text("import sys, struct, time\nfrom pathlib import Path\n"
                     "Path(sys.argv[1]).write_bytes(struct.pack('<IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))\n"
                     + body)
    return child


def _capture_with(monkeypatch, tmp_path, child, args):
    out = tmp_path / "x.pcap"
    monkeypatch.setattr(capture, "inspect", lambda *a, **k: _info())
    monkeypatch.setattr(capture, "ptp_status", lambda *a, **k: _ptp())
    monkeypatch.setattr(capture, "build_command", lambda *a, **k: [sys.executable, str(child), str(out)])
    rc = main(["capture", "-i", "eth1", "-w", str(out)] + args)
    return rc, json.loads((tmp_path / "x.pcap.json").read_text())


def test_capture_failure_is_not_reported_as_success(monkeypatch, tmp_path, capsys):
    child = _fake_tcpdump(tmp_path, "print('tcpdump: write: No space left on device\\n10 packets captured\\n"
                                    "10 packets received by filter\\n0 packets dropped by kernel', file=sys.stderr)\n"
                                    "sys.exit(1)\n")
    rc, meta = _capture_with(monkeypatch, tmp_path, child, ["--count", "10"])
    assert rc == 1 and meta["status"] == "failed" and meta["exit_code"] == 1
    assert "No space left on device" in meta["stderr_tail"] and meta["tcpdump_stats"]["captured"] == 10
    assert "did not complete normally" in capsys.readouterr().err
    assert "percentile" not in meta["json_encoding"]          # the metadata has no percentile rows


def test_capture_stopped_at_the_requested_time_is_complete(monkeypatch, tmp_path):
    child = _fake_tcpdump(tmp_path, "time.sleep(30)\n")       # stopped by our SIGINT
    rc, meta = _capture_with(monkeypatch, tmp_path, child, ["--duration", "1s"])
    assert rc == 0 and meta["status"] == "complete"


# ---------------------------------------------------------------- real capture (root and tcpdump only)
@pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("tcpdump"), reason="needs root and tcpdump")
def test_real_capture_on_loopback(tmp_path):
    out = str(tmp_path / "lo.pcap")
    port = 40000 + os.getpid() % 10000

    def send():
        time.sleep(1.0)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(200):
            s.sendto(i.to_bytes(4, "big") + b"pcaplat", ("127.0.0.1", port))
        s.close()

    t = threading.Thread(target=send)
    t.start()
    try:
        meta = capture.run_capture("lo", out, bpf=f"udp and dst port {port}", duration_s=3, echo=lambda *_: None)
    except RuntimeError as e:                       # e.g. a sandbox that forbids packet sockets
        pytest.skip(str(e))
    t.join()
    assert meta["status"] == "complete" and meta["tcpdump_stats"]["captured"] == 200
    assert meta["timestamp_type"] == "host"
    assert capture.load_sidecar(out)["interface"] == "lo"
    from pcaplat.reader import read_capture
    assert len(read_capture(out)) == 200
