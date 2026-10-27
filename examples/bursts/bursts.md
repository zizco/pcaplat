# Burst profile: a.pcap

Line rate 25G, 1,000,000 packets over 1.621 s, timestamp resolution 1 ns.

| Window | Busiest window (% of line rate) | Starts at (ns) | Windows above 90% |
|---:|---:|---:|---:|
| 10 us | 99.99% | 1760000000083650506 | 19 |
| 100 us | 62.01% | 1760000001377240621 | 0 |
| 1 ms | 8.55% | 1760000001458072816 | 0 |
| 10 ms | 3.09% | 1760000000562669924 | 0 |
| 1 s | 2.50% | 1760000000062197474 | 0 |

Average from the first frame's start to the last frame's end: 2.488% of line rate.

Only frames that start and finish serializing inside a window are counted. On one link, a peak can exceed 100% only by timestamp rounding, about two timestamp resolutions over the window length; a peak beyond line rate plus that allowance means the capture aggregates several links (fan-in). Timestamps are assumed to mark the start of each frame.

![Burst profile](bursts.png)
