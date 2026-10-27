import numpy as np

from pcaplat.layout import compute_layout
from pcaplat.match import KeySpec, packet_keys
from pcaplat.reader import read_capture
from pcaplat.synth import udp_frame, write_pcap_ns


def _cap(tmp_path, frames, name="x.pcap"):
    write_pcap_ns(tmp_path / name, [(1_760_000_000_000_000_000 + i, f) for i, f in enumerate(frames)])
    return read_capture(str(tmp_path / name))


def test_fast_and_scalar_paths_agree(tmp_path, mixed_frames):
    cap = _cap(tmp_path, mixed_frames)
    fast = compute_layout(cap)
    slow = compute_layout(cap, force_scalar=True)
    assert fast.fast[:4].all()              # the IPv4 frames took the vectorized path
    for name in ("ok", "proto", "addr", "sport", "dport", "l3_end", "pay_off", "pay_end", "truncated"):
        assert np.array_equal(getattr(fast, name), getattr(slow, name)), name


def test_non_ip_is_not_keyed(tmp_path, mixed_frames):
    lay = compute_layout(_cap(tmp_path, mixed_frames))
    assert lay.ok.tolist() == [True] * 7 + [False]        # ARP is skipped


def test_padding_and_trailers_do_not_change_the_key(tmp_path):
    src, dst = bytes([10, 0, 0, 1]), bytes([233, 54, 12, 1])
    clean = udp_frame(b"SEQ-0001", src, dst, 30001, 31001, pad_to_min=False)
    padded = udp_frame(b"SEQ-0001", src, dst, 30001, 31001, pad_to_min=True)
    trailer = clean + b"\xab" * 16
    for mode in ("l4payload", "frame"):
        k = packet_keys(_cap(tmp_path, [clean, padded, trailer]), KeySpec.parse(mode))["key"].tolist()
        assert k[0] == k[1] == k[2], mode


def test_ttl_change_keeps_l4payload_key_but_not_frame_key(tmp_path):
    src, dst = bytes([10, 0, 0, 1]), bytes([233, 54, 12, 1])
    hop0 = udp_frame(b"SEQ-0002", src, dst, 30001, 31001, ttl=64)
    hop1 = udp_frame(b"SEQ-0002", src, dst, 30001, 31001, ttl=63)     # routed once
    cap = _cap(tmp_path, [hop0, hop1])
    l4 = packet_keys(cap, KeySpec.parse("l4payload"))["key"].tolist()
    fr = packet_keys(cap, KeySpec.parse("frame"))["key"].tolist()
    assert l4[0] == l4[1]
    assert fr[0] != fr[1]


def test_bytes_key_uses_only_the_field(tmp_path):
    src, dst = bytes([10, 0, 0, 1]), bytes([233, 54, 12, 1])
    a = udp_frame(b"\x00\x00\x00\x07" + b"AAAA", src, dst, 30001, 31001)
    b = udp_frame(b"\x00\x00\x00\x07" + b"BBBB", src, dst, 30001, 31001)
    short = udp_frame(b"\x00\x00", src, dst, 30001, 31001)               # field absent
    keys = packet_keys(_cap(tmp_path, [a, b, short]), KeySpec.parse("bytes:0:4"))
    assert len(keys) == 2 and keys["key"].iloc[0] == keys["key"].iloc[1]


def test_linux_sll_and_raw_ip_give_the_same_key_as_ethernet(tmp_path):
    import struct
    src, dst = bytes([10, 0, 0, 1]), bytes([233, 54, 12, 1])
    eth = udp_frame(b"SEQ-0003", src, dst, 30001, 31001, pad_to_min=False)
    ip_packet = eth[14:]
    sll = struct.pack("!HHH8sH", 0, 1, 6, b"\x02" * 6 + b"\x00\x00", 0x0800) + ip_packet
    k_eth = packet_keys(_cap(tmp_path, [eth], "eth.pcap"), KeySpec())["key"].tolist()
    write_pcap_ns(tmp_path / "sll.pcap", [(1, sll)], linktype=113)
    write_pcap_ns(tmp_path / "raw.pcap", [(1, ip_packet)], linktype=101)
    k_sll = packet_keys(read_capture(str(tmp_path / "sll.pcap")), KeySpec())["key"].tolist()
    k_raw = packet_keys(read_capture(str(tmp_path / "raw.pcap")), KeySpec())["key"].tolist()
    assert k_eth == k_sll == k_raw and len(k_eth) == 1
