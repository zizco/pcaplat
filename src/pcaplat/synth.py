"""Synthetic two-point captures with a known latency distribution.

Used for tests and demos, and to check the tool against ground truth before
trusting it on real captures. The model is deliberately simple but has the
features that make real tails hard to read:

  * market-data arrivals at point A (a 25G link) with exponential gaps (a
    Poisson process), each gap floored at the frame's serialization time;
  * periodic deterministic bursts at 25G line rate, which replace some of
    those gaps, into a 10G egress, so a FIFO queue builds (Lindley recursion)
    and overflows a finite buffer: queueing tail + drops;
  * a rare second mode (a periodic housekeeping stall);
  * rare random drops, cross-traffic seen only at B, and heartbeat packets
    with identical payloads (ambiguous keys): 50 heartbeats and 200 cross
    traffic packets, scaled down for captures under 1,000 packets (never a
    single heartbeat, which would be unique and therefore matchable).

The truth files give, for every delivered data packet, its timestamp at A
and its injected latency, so tests can check recovery packet by packet.
"""
from __future__ import annotations

import json
import os
import struct

import numpy as np

ETH_OVERHEAD_BITS = (4 + 20) * 8          # FCS + preamble/SFD/IFG


def ipv4_checksum(hdr: bytes) -> int:
    s = sum(struct.unpack("!10H", hdr))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def udp_frame(payload: bytes, src_ip: bytes, dst_ip: bytes, sport: int, dport: int,
              ttl: int = 64, vlan: int | None = None, pad_to_min: bool = True) -> bytes:
    dst_mac = b"\x01\x00\x5e" + bytes((dst_ip[1] & 0x7F, dst_ip[2], dst_ip[3])) if dst_ip[0] >= 224 else b"\x02" * 6
    eth = dst_mac + b"\x02\x00\x00\x00\x00\x01"
    eth += (struct.pack("!HH", 0x8100, vlan) if vlan is not None else b"") + b"\x08\x00"
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    total = 20 + len(udp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, ttl, 17, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack("!H", ipv4_checksum(ip)) + ip[12:]
    frame = eth + ip + udp + payload
    if pad_to_min and len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def write_pcap_ns(path: str, records, linktype: int = 1) -> None:
    """records: iterable of (ts_ns, frame_bytes). Nanosecond pcap, Ethernet by default."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, linktype))
        rec = struct.Struct("<IIII")
        for ts, frame in records:
            sec, nsec = divmod(int(ts), 1_000_000_000)
            f.write(rec.pack(sec, nsec, len(frame), len(frame)))
            f.write(frame)


def write_pcap_us(path: str, records) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        rec = struct.Struct("<IIII")
        for ts, frame in records:
            sec, nsec = divmod(int(ts), 1_000_000_000)
            f.write(rec.pack(sec, nsec // 1000, len(frame), len(frame)))
            f.write(frame)


def write_pcapng(path: str, records, tsresol: int = 9) -> None:
    """Minimal pcapng: one section, one Ethernet interface with if_tsresol."""
    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    exp = tsresol & 0x7F
    with open(path, "wb") as f:
        f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        opt = struct.pack("<HHB3x", 9, 1, tsresol) + struct.pack("<HH", 0, 0)
        f.write(block(1, struct.pack("<HHI", 1, 0, 65535) + opt))
        for ts, frame in records:
            if tsresol & 0x80:
                t = (int(ts) << exp) // 1_000_000_000
            else:
                t = int(ts) * 10 ** exp // 1_000_000_000
            body = struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(frame), len(frame)) + frame
            f.write(block(6, body))


def generate(out_dir: str, packets: int = 500_000, seed: int = 7,
             rate_pps: float = 2_000_000, ingress_bps: float = 25e9, egress_bps: float = 10e9,
             burst_every: int = 50_000, burst_len: int = 1_500, buffer_bytes: int = 64_000,
             base_ns: int = 450, stall_prob: float = 3e-4, stall_ns: int = 1_800,
             random_drop_prob: float = 2e-5, start_ns: int = 1_760_000_000_000_000_000) -> dict:
    """Write a.pcap and b.pcap plus truth.json, truth_ts_a.npy, truth_latency.npy and
    truth_dropped_ts_a.npy to out_dir."""
    if packets < 1:
        raise ValueError(f"packets must be at least 1, got {packets}")
    rng = np.random.default_rng(seed)
    os.makedirs(out_dir, exist_ok=True)
    src_ip, dst_ip, sport, dport = bytes([10, 0, 0, 1]), bytes([233, 54, 12, 1]), 30001, 31001

    payload_len = 60
    frame_len = 14 + 20 + 8 + payload_len
    wire_bits = frame_len * 8 + ETH_OVERHEAD_BITS
    ser_in = wire_bits / ingress_bps * 1e9
    ser_out = wire_bits / egress_bps * 1e9

    # Arrival times at A. The model works in ns relative to the start of the
    # capture and only adds the epoch offset as an integer at the end: a float64
    # holding ~1.76e18 ns can only represent multiples of 256 ns.
    gaps = rng.exponential(1e9 / rate_pps, packets)
    gaps = np.maximum(gaps, ser_in)                         # cannot beat line rate
    for b0 in range(burst_every, packets, burst_every):     # back-to-back bursts at 25G
        gaps[b0: b0 + burst_len] = ser_in
    rel = np.round(np.cumsum(gaps)).astype(np.int64)
    rel = np.maximum(rel, np.maximum.accumulate(rel))       # keep order after rounding
    t_a = start_ns + rel

    # FIFO at the 10G egress (Lindley), finite buffer -> overflow drops
    wait = np.zeros(packets)
    dropped = np.zeros(packets, dtype=bool)
    w, last_t, max_wait = 0.0, 0.0, buffer_bytes * 8 / egress_bps * 1e9
    for i in range(packets):
        ti = float(rel[i])
        w = max(0.0, w - (ti - last_t))
        last_t = ti
        if w > max_wait:
            dropped[i] = True
            continue
        wait[i] = w
        w += ser_out
    overflow = dropped.copy()
    dropped |= rng.random(packets) < random_drop_prob

    jitter = rng.lognormal(mean=np.log(20.0), sigma=0.5, size=packets)
    stall = (rng.random(packets) < stall_prob) * stall_ns
    latency = np.round(base_ns + ser_out + jitter + wait + stall).astype(np.int64)
    t_b = t_a + latency

    # Heartbeats take the place of 50 data packets: identical payloads, so their
    # keys are ambiguous and the tool must exclude them. A single heartbeat
    # would be unique, hence matchable, so small captures get none or at least two.
    n_hb = min(50, packets // 10)
    is_hb = np.zeros(packets, dtype=bool)
    is_hb[rng.choice(packets, size=n_hb if n_hb >= 2 else 0, replace=False)] = True
    hb_frame = udp_frame(b"HEARTBEAT".ljust(payload_len, b"."), src_ip, dst_ip, sport, dport)
    frames = [hb_frame if is_hb[i] else
              udp_frame(struct.pack("!Q", i + 1) + b"MD" + bytes(payload_len - 10), src_ip, dst_ip, sport, dport)
              for i in range(packets)]
    # cross traffic that only exists at B
    xb_idx = rng.choice(packets, size=min(200, packets // 5), replace=False)

    rec_a = [(int(t_a[i]), frames[i]) for i in range(packets)]
    rec_b = [(int(t_b[i]), frames[i]) for i in range(packets) if not dropped[i]]
    rec_b += [(int(t_b[i]) + 11, udp_frame(b"XTRAFFIC" + struct.pack("!I", k).ljust(32, b"x"),
                                           bytes([10, 9, 9, 9]), bytes([10, 0, 0, 2]), 5000, 6000))
              for k, i in enumerate(xb_idx)]
    rec_b.sort(key=lambda r: r[0])
    write_pcap_ns(os.path.join(out_dir, "a.pcap"), rec_a)
    write_pcap_ns(os.path.join(out_dir, "b.pcap"), rec_b)

    data = ~is_hb
    np.save(os.path.join(out_dir, "truth_ts_a.npy"), t_a[data & ~dropped])
    np.save(os.path.join(out_dir, "truth_latency.npy"), latency[data & ~dropped])
    np.save(os.path.join(out_dir, "truth_dropped_ts_a.npy"), t_a[data & dropped])
    truth = {
        "packets": packets,
        "delivered": int((data & ~dropped).sum()),            # unique data packets seen at B
        "dropped": int(dropped.sum()),
        "dropped_data": int((data & dropped).sum()),
        "overflow_drops": int(overflow.sum()), "random_drops": int((dropped & ~overflow).sum()),
        "heartbeats": int(is_hb.sum()), "heartbeats_delivered": int((is_hb & ~dropped).sum()),
        "cross_traffic_b": len(xb_idx),
        "ingress_bps": ingress_bps, "egress_bps": egress_bps, "buffer_bytes": buffer_bytes,
        "seed": seed,
    }
    with open(os.path.join(out_dir, "truth.json"), "w") as f:
        json.dump(truth, f, indent=2)
    return truth
