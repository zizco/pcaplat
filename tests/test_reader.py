import struct

import numpy as np
import pytest

from pcaplat.reader import read_capture
from pcaplat.synth import write_pcap_ns, write_pcap_us, write_pcapng

T0 = 1_760_000_000_123_456_789


def _records(frames):
    return [(T0 + 1_000 * i + i, f) for i, f in enumerate(frames)]


def test_pcap_nanosecond_keeps_every_ns(tmp_path, mixed_frames):
    recs = _records(mixed_frames)
    write_pcap_ns(tmp_path / "x.pcap", recs)
    cap = read_capture(str(tmp_path / "x.pcap"))
    assert cap.fmt == "pcap" and cap.ts_resolution == "1 ns"
    assert cap.ts_ns.dtype == np.int64
    assert cap.ts_ns.tolist() == [t for t, _ in recs]
    assert cap.cap_len.tolist() == [len(f) for _, f in recs]
    assert bytes(cap.packet(2)) == recs[2][1]


def test_pcap_microsecond_truncates_to_us(tmp_path, mixed_frames):
    recs = _records(mixed_frames)
    write_pcap_us(tmp_path / "x.pcap", recs)
    cap = read_capture(str(tmp_path / "x.pcap"))
    assert cap.ts_resolution == "1 us"
    assert cap.ts_ns.tolist() == [t - t % 1000 for t, _ in recs]


def test_big_endian_pcap(tmp_path):
    frame = b"\x00" * 60
    with open(tmp_path / "be.pcap", "wb") as f:
        f.write(struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack(">IIII", 1_700_000_000, 999_999_999, 60, 60) + frame)
    cap = read_capture(str(tmp_path / "be.pcap"))
    assert cap.ts_ns.tolist() == [1_700_000_000_999_999_999]


@pytest.mark.parametrize("tsresol,step", [(9, 1), (6, 1000), (0x80 | 30, None)])
def test_pcapng_resolutions(tmp_path, mixed_frames, tsresol, step):
    recs = _records(mixed_frames)
    write_pcapng(tmp_path / "x.pcapng", recs, tsresol=tsresol)
    cap = read_capture(str(tmp_path / "x.pcapng"))
    assert cap.fmt == "pcapng"
    got = cap.ts_ns.tolist()
    want = [t for t, _ in recs]
    if step:
        assert got == [t - t % step for t in want]
    else:   # 2^-30 s units: within one unit (~0.93 ns)
        assert all(abs(g - w) <= 1 for g, w in zip(got, want))
    assert cap.cap_len.tolist() == [len(f) for _, f in recs]


def test_truncated_file_stops_cleanly(tmp_path, mixed_frames):
    write_pcap_ns(tmp_path / "x.pcap", _records(mixed_frames))
    data = (tmp_path / "x.pcap").read_bytes()
    (tmp_path / "cut.pcap").write_bytes(data[:-5])
    cap = read_capture(str(tmp_path / "cut.pcap"))
    assert len(cap) == len(mixed_frames) - 1


def test_unknown_format(tmp_path):
    (tmp_path / "x.bin").write_bytes(b"not a capture at all")
    with pytest.raises(ValueError):
        read_capture(str(tmp_path / "x.bin"))
