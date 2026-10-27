# Measuring a path in your own network

This guide takes you from "I want the one-way latency between these two points" to a report you can defend. It assumes Linux capture hosts. The analysis itself runs anywhere Python runs.

```
   point A                                                     point B
   (where the packet enters                                    (where it leaves
    what you want to measure)                                   what you want to measure)
        |                                                            |
   capture a.pcap  ------------->  pcaplat latency  <------------  capture b.pcap
                                         |
                    report.md, summary.json, ccdf.png, latencies.parquet
```

What you measure is exactly the time between the two timestamping points, nothing more. If A is a NIC on the feed handler and B is a NIC on the order gateway, the result includes the cables, the switches in between, and nothing of the software on either host.

## 1. Choose the capture points

| Setup | Clocks | Typical use | Options for `pcaplat latency` |
|---|---|---|---|
| Optical taps on both sides of a device, into one capture card or appliance | One | Latency of a switch, a firewall, an L1 device | `--same-clock`, and `--key frame` if the device rewrites nothing |
| Two hosts with NIC hardware timestamps, both disciplined by PTP | Two | Host-to-host latency across a fabric | `--clock-error` set from the PTP offsets |
| One host, two NICs | Two hardware clocks, one per NIC, unless one is slaved to the other | Lab tests on one server | Slave one NIC clock to the other with `phc2sys`, or treat it as two clocks |
| Software timestamps (any NIC) | The system clock | Millisecond-scale questions | Do not read microseconds |

Avoid SPAN or mirror ports for latency. The mirror copy goes through its own queue in the switch, can be dropped when the port is busy, and can be reordered. Use them to find traffic, not to time it.

## 2. Check each capture host

On each host that will capture, run:

```
sudo pcaplat doctor eth1
```

It checks that tcpdump is installed, whether the NIC timestamps received packets in hardware, whether tcpdump can use that clock, and the interrupt coalescing that delays software timestamps. For the clock, a running ptp4l is not taken as proof: doctor asks ptp4l (through `pmc`) which interfaces its ports use, looks at every port on this NIC's clock (a boundary clock has several), and requires a SLAVE port with hardware timestamping, an explicit answer that a grandmaster is present, and a few offset samples. Without that evidence it says "not verified" and makes no accuracy claim. Use `--ptp-uds` and `--ptp-domain` when ptp4l does not use the default socket or domain 0. A host ready for sub-microsecond work looks like this:

```
OK    tcpdump version 4.99.4
OK    eth1 timestamps received packets in hardware (PTP hardware clock /dev/ptp2).
OK    tcpdump timestamp types on eth1: host, adapter_unsynced
OK    ptp4l disciplines this NIC clock: port eth1 is SLAVE with hardware timestamping; offset from master up to 7 ns over 5 samples.
INFO  Verdict: hardware timestamps on a NIC clock that ptp4l keeps close to its master. Sub-microsecond work is possible. These offsets show variation only: a constant bias, such as path asymmetry, is invisible here and must be bounded separately (docs/MEASURING.md, section 3).
```

When the clock cannot be verified, doctor says so:

```
WARN  PTP synchronization of this NIC clock is not verified: ptp4l did not answer pmc (run as root; ...).
INFO  Verdict: hardware timestamps, synchronization not verified: no accuracy claim between two hosts. Two points captured on this one NIC clock remain comparable.
```

A host without hardware timestamps looks like this, and the report will carry the same warnings:

```
WARN  eth1 has no hardware receive timestamps: the kernel will timestamp packets in software, after the NIC and the interrupt path.
WARN  interrupt coalescing rx-usecs = 50 on eth1: software timestamps can be up to about 50 us late. ...
INFO  Verdict: software timestamps. Fine for millisecond-scale questions; do not read differences of a few microseconds.
```

What you need installed: `tcpdump` (always), `ethtool` (for the checks), `linuxptp` (if you use PTP). Capturing needs root, or the capabilities CAP_NET_RAW and CAP_NET_ADMIN. If pcaplat is installed in a virtual environment, `sudo` will not find it on its path: run `sudo "$(which pcaplat)" doctor eth1` instead.

## 3. Get the clocks right

The latency of every packet includes the offset between the clocks at A and B. Three rules:

1. **Same timestamp type at both points.** A NIC clock disciplined by PTP usually runs on TAI, which is 37 seconds ahead of the UTC system clock. Hardware at A and software at B gives you a 37-second "latency". `pcaplat capture` uses the NIC clock whenever the NIC has one; on a mixed pair, force `--timestamp host` on both, or fix the host without hardware timestamps.
2. **Bound the clock error, not just its noise.** The error between the clocks at A and B has two parts. The variation is what ptp4l shows: its `master offset` lines (`ptp4l -i eth1 -s -m`), the samples `pcaplat doctor` and `pcaplat capture` record. The constant bias is what it cannot show: path asymmetry between each host and the grandmaster, uncorrected cable and timestamp-point delays, a different grandmaster or domain at each end. A bias of 5 µs with perfectly stable offsets still adds 5 µs to every latency. So `--clock-error` must cover both. Two ways to bound the bias:
   - **Calibrate against one clock.** Once, capture both points on a single device (for example two ports of one capture card) and compare with the two-host result over the same traffic. The difference is the bias of the two-clock setup.
   - **Measure both directions.** On a path that is symmetric, send traffic A to B and B to A. A clock offset adds to one direction and subtracts from the other, so half the difference between the two minimum latencies estimates it. It is only as good as the symmetry assumption.

   Without one of these, state the clock error as unknown rather than quoting the offset samples as an error bound.
3. **One host, two NICs.** Each NIC has its own hardware clock. Slave one to the other, for example `phc2sys -s eth1 -c eth2 -O 0 -m` (check the options against your linuxptp version), or capture both points on one capture card instead.

A practical rule for the result: a difference smaller than about ten times the clock error is not a finding.

## 4. Capture

Start B before A, and stop it after A, so that every packet sent at A had a chance to be seen at B. pcaplat only counts losses over the time B was observing, but the overlap should be generous.

```
host-b$ sudo pcaplat capture -i eth1 -w b.pcap --filter 'udp and dst port 31001' --duration 330s
host-a$ sudo pcaplat capture -i eth1 -w a.pcap --filter 'udp and dst port 31001' --duration 300s
```

Each run writes the capture and a small metadata file next to it (`a.pcap.json`): interface, timestamp source, the PTP check at the start and at the end of the capture, the packets the capture path itself dropped, and whether tcpdump completed normally. If it did not (disk full, permissions), `pcaplat capture` exits with an error and the metadata says `failed`, with tcpdump's own message. Copy both files of each pair to wherever you analyse. `pcaplat latency` reads the metadata automatically.

Good practice:

- **Filter to the flows you measure.** The filter runs in the kernel and is the cheapest way to avoid capture drops. Use the same filter at both points.
- **Keep whole packets** (the default). A short snap length makes the default key unusable; see `--key bytes:` below if you must truncate.
- **Watch capture drops.** `pcaplat capture` prints them, and the report repeats them. A packet dropped by the capture path looks exactly like a packet lost by the network. If drops appear, tighten the filter, raise `--buffer-mb`, write to a faster disk, or use a capture card.
- **Line rate is a hardware job.** A server writing every packet of a busy 10G or 25G link to disk with tcpdump will often drop some. For full line-rate capture, use a capture card or appliance that writes pcap or pcapng with nanosecond timestamps; pcaplat reads those files directly.

If you cannot install pcaplat on a production host, tcpdump alone does the same capture. Only the metadata file is missing, so state the timestamp source and clock on the `pcaplat latency` command line instead:

```
sudo tcpdump -i eth1 -n -s 0 -B 262144 --time-stamp-precision=nano -j adapter_unsynced \
     -w a.pcap 'udp and dst port 31001'
```

Drop `-j adapter_unsynced` on a NIC without hardware timestamps (`tcpdump -J -i eth1` lists what the NIC offers). For long captures, let tcpdump rotate files (`-C` or `-G`) and merge each side into one file before analysis, for example with `mergecap -w a.pcapng a_*.pcap` from Wireshark's tools (pcaplat reads pcapng).

## 5. Analyse

```
pcaplat info a.pcap b.pcap
pcaplat latency a.pcap b.pcap --dst-port 31001 \
    --label "feed handler NIC to order gateway NIC" --clock-error 50ns --out report/
pcaplat bursts a.pcap --line-rate 10G --out bursts/
```

`pcaplat info` shows the resolution, interfaces, packet counts, capture metadata and anything wrong with the files. Read it first: a microsecond capture makes sub-microsecond results meaningless.

Choose the key from what sits between A and B:

| Between A and B | `--key` |
|---|---|
| A router or L3 switch (TTL, checksum and MAC addresses change) | `l4payload` (default) |
| An L1 device or L2 switch that rewrites nothing | `frame` |
| Anything, when the payload carries a sequence number at a known place | `bytes:OFFSET:LENGTH`, for example `bytes:0:8` |

Other options you will use:

- `--max-latency` (default 1 ms): pairs later than this are reported as late, not matched. Raise it for slow or congested paths.
- `--allow-negative 5us`: keep small negative latencies while you investigate a clock offset, instead of rejecting them.
- `--dst-ip`, `--dst-port`, `--proto`: analyse one flow out of a larger capture.

## 6. Read the report

In this order:

1. **Sanity checks** (section 4): undeclared clock error, negative latencies, coarse timestamps, capture drops, packets that could not be keyed. Anything marked CHECK can invalidate the numbers above it.
2. **The loss cohort table**: how many packets were matched, late, clock-invalid or lost.
3. **The percentiles**: trust only the rows marked reliable (at least 100 samples beyond them, by default), and use the loss-aware table when there are losses.
4. **The CCDF**: the shape of the tail, a second mode, the maximum.

`latencies.parquet` has one row per matched packet (both timestamps, latency, length) for your own analysis, for example in pandas.

## 7. When the numbers look wrong

| Symptom | Likely cause | What to do |
|---|---|---|
| Almost everything lost, few matches | The key does not survive the path (NAT, rewritten payload), different filters at A and B, or captures that barely overlap in time | Check `pcaplat info` durations; try `--key bytes:...` on a sequence number |
| Every latency around 37 s, or everything late | Hardware timestamps at one point, software at the other (TAI against UTC) | Same timestamp type at both points |
| Many negative latencies | The clock at B is behind the clock at A | Fix PTP; meanwhile `--allow-negative` shows the distribution |
| Latencies stable but higher than expected by a fixed amount | A constant clock bias (path asymmetry, a different grandmaster) | Bound the bias as in section 3; offset samples near zero do not rule it out |
| The capture reports `status failed` or `killed` | tcpdump stopped on an error (disk full, permissions) or did not stop cleanly | Read `stderr_tail` in the `.json` file; the capture may be partial |
| Losses, and the report mentions capture drops | The capture path lost them, not the network | See "Watch capture drops" above |
| Results move in steps of 1 µs | A microsecond capture | Capture with `--time-stamp-precision=nano` (pcaplat capture does) |
| Many ambiguous keys | Repeated payloads (heartbeats, retransmissions) | Key on a sequence number with `--key bytes:...` |
| Many packets "cut by the snap length" | Short snap length | Capture whole packets, or key on a field inside the captured bytes |
| p99.99 marked unreliable | Too few samples | Capture longer: about a million samples for a stable p99.99 |

## 8. Before you share a number

- Both timestamp sources and the clock are stated in the report (from the metadata files, or on the command line).
- The clock error is stated, covers the constant bias as well as the variation, and the effect you report is at least ten times larger.
- Both captures completed normally (`status complete` in their metadata).
- No capture drops, or they are accounted for.
- The percentiles you quote are marked reliable.
- If there were losses, the loss-aware table is the one you quote.
