"""Cross-validation 3: a real capture made by the Linux kernel.

An AF_PACKET socket on the loopback interface sees every datagram twice:
once on transmit (pkttype OUTGOING) and once on receive (pkttype HOST), each
with a kernel nanosecond timestamp (SO_TIMESTAMPNS). That is a genuine
two-point measurement on one clock. The two views are written with dpkt
(not pcaplat's writer), analysed by pcaplat, and compared with latencies
computed independently here from the raw socket data.
"""
import os
import socket
import struct
import sys
import threading
import time
from decimal import Decimal

import dpkt
import numpy as np

from pcaplat.match import KeySpec, PacketFilter, match, packet_keys
from pcaplat.reader import read_capture
from pcaplat.stats import summarize

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
N = int(sys.argv[2]) if len(sys.argv) > 2 else 20_000
PORT = 31001
SO_TIMESTAMPNS = 35
PACKET_HOST, PACKET_OUTGOING = 0, 4

cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
cap.bind(("lo", 0))
cap.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
cap.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 << 20)
cap.settimeout(1.0)

sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sink.bind(("127.0.0.1", PORT))
sink.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 << 20)


def drain():
    sink.settimeout(2.0)
    try:
        while True:
            sink.recv(2048)
    except socket.timeout:
        pass


def send():
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(N):
        tx.sendto(struct.pack("!Q", i) + b"MD-LOOPBACK" + bytes(40), ("127.0.0.1", PORT))
        if i % 500 == 499:
            time.sleep(0.002)          # bursts of 500, then a pause


captured = {PACKET_OUTGOING: [], PACKET_HOST: []}
threading.Thread(target=drain, daemon=True).start()
t = threading.Thread(target=send)
t.start()
deadline = time.time() + 30
while time.time() < deadline:
    try:
        data, anc, _, addr = cap.recvmsg(65535, 1024)
    except socket.timeout:
        if not t.is_alive():
            break
        continue
    ts = None
    for level, ctype, cdata in anc:
        if level == socket.SOL_SOCKET and ctype == SO_TIMESTAMPNS:
            sec, nsec = struct.unpack("qq", cdata[:16])
            ts = sec * 1_000_000_000 + nsec
    if ts is not None and addr[2] in captured:
        captured[addr[2]].append((ts, data))
t.join()

for kind, name in ((PACKET_OUTGOING, "lo_tx.pcap"), (PACKET_HOST, "lo_rx.pcap")):
    with open(f"{OUT}/{name}", "wb") as f:
        w = dpkt.pcap.Writer(f, nano=True)
        for ts, data in captured[kind]:
            w.writepkt(data, ts=Decimal(ts) / Decimal(1_000_000_000))


# independent reference: match by the sequence number in the payload
def by_seq(items):
    out = {}
    for ts, data in items:
        if len(data) >= 42 + 8 and data[23] == 17 and struct.unpack("!H", data[36:38])[0] == PORT:
            out[struct.unpack("!Q", data[42:50])[0]] = ts
    return out


tx, rx = by_seq(captured[PACKET_OUTGOING]), by_seq(captured[PACKET_HOST])
ref = np.array(sorted(rx[s] - tx[s] for s in tx.keys() & rx.keys()), dtype=np.int64)

a, b = read_capture(f"{OUT}/lo_tx.pcap"), read_capture(f"{OUT}/lo_rx.pcap")
flt = PacketFilter(dst_port=PORT)
res = match(packet_keys(a, KeySpec(), flt), packet_keys(b, KeySpec(), flt))
got = np.sort(res.matched["latency_ns"].to_numpy())

late_ref = int((ref > 1_000_000).sum())
ref_in = ref[ref <= 1_000_000]
print(f"sent {N:,}; kernel saw {len(tx):,} on transmit and {len(rx):,} on receive")
print(f"reference: {len(ref_in):,} within 1 ms, {late_ref} later; "
      f"pcaplat: {len(got):,} matched, {res.counts['late_beyond_window']} late, {res.counts['lost']} lost, "
      f"{res.counts['extra_b']} extra")
print("latencies identical to the independent reference:", np.array_equal(ref_in, got))
s = summarize(got)
p = {r['percentile']: r for r in s['percentiles']}
print(f"loopback one-way (kernel tx tap to rx tap): min {s['min_ns']:.0f} ns, p50 {p[50.0]['value_ns']:.0f} ns, "
      f"p99 {p[99.0]['value_ns']:.0f} ns, p99.9 {p[99.9]['value_ns']:.0f} ns, max {s['max_ns']:.0f} ns")
assert np.array_equal(ref_in, got)
assert res.counts["late_beyond_window"] == late_ref
assert res.counts["lost"] == 0 and res.counts["extra_b"] == 0
print("OK  real kernel capture")
