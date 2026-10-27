"""Cross-validation 1 and 2: files written by third-party writers (scapy, dpkt),
read back by pcaplat and compared with scapy's own reading and dissection."""
import os
import random
import sys
from decimal import Decimal

import numpy as np
from scapy.all import IP, TCP, UDP, Dot1Q, Ether, IPv6, Raw, rdpcap
from scapy.utils import PcapNgWriter, PcapWriter
import dpkt

from pcaplat.layout import compute_layout
from pcaplat.reader import read_capture

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
rng = random.Random(42)
T0 = 1_760_000_000_123_456_789


def make_packets(n=3000):
    pkts = []
    for i in range(n):
        kind = rng.choice(["udp", "vlan", "qinq", "tcp", "v6", "small"])
        pl = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200)))
        if kind == "udp":
            p = Ether() / IP(src="10.0.0.1", dst="233.54.12.1") / UDP(sport=30001, dport=31001) / Raw(pl)
        elif kind == "vlan":
            p = Ether() / Dot1Q(vlan=100) / IP(src="10.0.0.2", dst="10.0.0.3") / UDP(sport=1, dport=2) / Raw(pl)
        elif kind == "qinq":
            p = Ether() / Dot1Q(vlan=10) / Dot1Q(vlan=20) / IP(src="10.0.0.4", dst="10.0.0.5") / UDP(sport=3, dport=4) / Raw(pl)
        elif kind == "tcp":
            p = Ether() / IP(src="10.1.0.1", dst="10.1.0.2") / TCP(sport=40000, dport=9000, options=[("NOP", None)] * 4) / Raw(pl)
        elif kind == "v6":
            p = Ether() / IPv6(src="2001:db8::1", dst="ff02::1") / UDP(sport=5, dport=6) / Raw(pl)
        else:
            p = Ether() / IP(src="10.2.0.1", dst="10.2.0.2") / UDP(sport=7, dport=8) / Raw(pl[:2])
        raw = bytes(p)
        if len(raw) < 60:                       # pad to the Ethernet minimum, as a NIC does on the wire
            raw += bytes(60 - len(raw))
            PADDED.add(i)
        p = Ether(raw)
        ts = T0 + i * 1_013 + rng.randint(0, 999)
        p.time = Decimal(ts) / Decimal(1_000_000_000)
        pkts.append((ts, p))
    return pkts


def expected_fields(p):
    """Ports and L4 payload according to scapy's dissection."""
    l4 = p.getlayer(UDP) or p.getlayer(TCP)
    ip = p.getlayer(IP) or p.getlayer(IPv6)
    if l4 is None:
        return None
    payload = bytes(l4.payload)
    if p.getlayer(UDP) is not None:
        payload = payload[: l4.len - 8]                       # strip Ethernet padding
    elif p.getlayer(IP) is not None:
        ip_payload_len = ip.len - ip.ihl * 4
        payload = payload[: ip_payload_len - l4.dataofs * 4]
    return l4.sport, l4.dport, payload


def check(path, pkts, label, ts_exact=True):
    cap = read_capture(path)
    lay = compute_layout(cap)
    assert len(cap) == len(pkts), (label, len(cap), len(pkts))
    want_ts = np.array([t for t, _ in pkts], dtype=np.int64)
    if ts_exact:
        assert np.array_equal(cap.ts_ns, want_ts), label
    else:
        assert np.all(np.abs(cap.ts_ns - want_ts) <= 1_000), label
    B = bytes(cap.buf)
    errors = 0
    for i, (_, p) in enumerate(pkts):
        assert bytes(cap.packet(i)) == bytes(p), (label, i)
        exp = expected_fields(p)
        if exp is None:
            continue
        sport, dport, payload = exp
        got = B[int(lay.pay_off[i]): int(lay.pay_end[i])]
        if (int(lay.sport[i]), int(lay.dport[i]), got) != (sport, dport, payload):
            errors += 1
    assert errors == 0, (label, errors)
    # scapy reading the same file must agree on timestamps
    sc = rdpcap(path)
    sc_ts = np.array([int(Decimal(x.time) * 1_000_000_000) for x in sc], dtype=np.int64)
    assert np.array_equal(sc_ts, cap.ts_ns), (label, "scapy disagrees")
    short = int((cap.cap_len < 60).sum())
    assert short == 0, (label, "frames shorter than the Ethernet minimum", short)
    print(f"OK  {label:32s} {len(cap):5d} packets ({len(PADDED)} padded to 60 bytes), timestamps, bytes and "
          f"L4 fields identical (fast path {int(lay.fast.sum())}, scalar path {int((lay.ok & ~lay.fast).sum())})")


PADDED: set[int] = set()                # packets this script padded to the Ethernet minimum
pkts = make_packets()

w = PcapWriter(f"{OUT}/scapy_ns.pcap", nano=True, linktype=1, sync=True)
for _, p in pkts:
    w.write(p)
w.close()
check(f"{OUT}/scapy_ns.pcap", pkts, "scapy pcap (nanosecond)")

w = PcapNgWriter(f"{OUT}/scapy.pcapng")
for _, p in pkts:
    w.write(p)
w.close()
check(f"{OUT}/scapy.pcapng", pkts, "scapy pcapng", ts_exact=False)

with open(f"{OUT}/dpkt_ns.pcap", "wb") as f:
    wr = dpkt.pcap.Writer(f, nano=True)
    for ts, p in pkts:
        wr.writepkt(bytes(p), ts=Decimal(ts) / Decimal(1_000_000_000))
check(f"{OUT}/dpkt_ns.pcap", pkts, "dpkt pcap (nanosecond)", ts_exact=False)

with open(f"{OUT}/dpkt_us.pcap", "wb") as f:
    wr = dpkt.pcap.Writer(f)
    for ts, p in pkts:
        wr.writepkt(bytes(p), ts=Decimal(ts) / Decimal(1_000_000_000))
# dpkt rounds (not truncates) to the microsecond when writing: compare with the intended
# time within 1 us; the exact check is the agreement with scapy reading the same file
check(f"{OUT}/dpkt_us.pcap", pkts, "dpkt pcap (microsecond)", ts_exact=False)
