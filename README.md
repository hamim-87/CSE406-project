# CSE 406: TCP Optimistic ACK Attack & Defense

A Mininet-based lab that demonstrates the **TCP Optimistic ACK attack** — a
receiver-side exploit where a malicious client ACKs data it hasn't actually
received, tricking the sender's congestion control into inflating `cwnd` far
beyond what the network path can sustain. This starves competing honest
flows and can overrun bottleneck queues. The lab also implements and
evaluates an **eBPF/XDP-based defense** that filters non-compliant ACKs at
the server's network ingress before they reach the kernel's TCP stack.

## How it works

A dumbbell topology is built with Mininet:

```
h1 (NGINX server, 10.0.0.1)
  |
 r1 (Linux router — bottleneck shaper: tc tbf + netem)
  |
 s1 (OVS switch)
 /  \
h2    h3
(attacker,   (honest client,
 10.0.0.3)    10.0.0.2)
```

- **h1** serves a 200 MB `video.mp4` over NGINX.
- **h3** is an honest client doing a normal HTTP download.
- **h2** performs the optimistic-ACK attack: it completes a real TCP
  handshake and HTTP GET via raw sockets (Scapy), then paces forged ACKs at a
  target steal-rate that acknowledge data the server has sent but that h2 has
  **not** received yet. This hides bottleneck loss from the server (so it
  never backs off) while a safety clamp keeps the ACK number at/below the
  server's real `snd_max`, so the connection is never reset by the kernel's
  ACK-validation rules.
- **r1** shapes the link to a fixed bandwidth/delay/queue depth to make the
  attack's effect on the bottleneck observable.
- Telemetry samples the server's TCP socket state (`ss -ti`) and the
  bottleneck queue (`tc -s qdisc`) throughout each run.
- The **defense** (`defense/defense_inspector.c`) is a pair of eBPF programs
  sharing one flow table:
  1. An **XDP ingress** filter on the server drops client ACKs that either
     acknowledge data beyond `snd_max` (sent-bound check) or advance the ACK
     number faster than the path bandwidth + margin allows (rate-bound check,
     a per-flow token bucket).
  2. A **TC egress** program on the same interface watches the server's
     outgoing data and records each flow's true `snd_max` directly in the
     datapath — so the sent-bound check has an accurate, absolute sequence
     bound with no fragile userspace bookkeeping.

  `defense/defense_loader.py` loads both programs with shared (pinned) maps,
  attaches them, and reports live drop counters.

## Repository layout

| Path | Purpose |
|---|---|
| [src/topology.py](src/topology.py) | Builds the Mininet dumbbell topology and starts NGINX |
| [src/honest_client.py](src/honest_client.py) | Legitimate downloader; logs per-second goodput |
| [src/optimistic_client.py](src/optimistic_client.py) | Scapy-based optimistic-ACK attacker |
| [src/telemetry.py](src/telemetry.py) | Samples TCP (`ss`) and queue (`tc`) state to CSV |
| [defense/defense_inspector.c](defense/defense_inspector.c) | XDP/eBPF ACK filter (sent-bound + rate-bound checks) |
| [defense/defense_loader.py](defense/defense_loader.py) | Loads the XDP program, updates `snd_max`, prints stats |
| [config/nginx.conf](config/nginx.conf) | Server config, incl. `limit_rate` as an app-layer backstop |
| [scripts/install_deps.sh](scripts/install_deps.sh) | Installs all system dependencies (Ubuntu/Debian) |
| [scripts/run_experiment.sh](scripts/run_experiment.sh) | Orchestrates baseline/attack/defense scenarios |
| [scripts/plot_results.py](scripts/plot_results.py) | Generates comparison plots from result CSVs |

## Requirements

- Linux with root access (Mininet needs real network namespaces — this will
  **not** work in an unprivileged container or under WSL1).
- A kernel with eBPF/XDP support (for the defense scenario).
- Ubuntu 20.04+/Debian 11+ recommended (`install_deps.sh` uses `apt-get`).

Install everything with:

```bash
sudo bash scripts/install_deps.sh
```

This installs Mininet, Open vSwitch, NGINX, `python3-scapy`, `matplotlib`,
`iproute2`, and the eBPF toolchain (`clang`, `llvm`, `libbpf-dev`,
`bpftool`), plus `tcpdump`/`iperf3`/`net-tools`/`curl`.

## Running an experiment

```bash
sudo ./scripts/run_experiment.sh [baseline|attack|defense|all]
```

- `baseline` — honest client only, no attack.
- `attack` — honest client + optimistic-ACK attacker, no defense.
- `defense` — same attack, with the XDP filter loaded on the server.
- `all` (default) — runs all three scenarios back to back.

Each scenario:
1. Spins up the Mininet topology and starts NGINX on h1.
2. Starts the telemetry sampler on h1.
3. Starts the honest download client on h3 (and, for attack/defense, the
   optimistic-ACK attacker on h2 after a short warm-up).
4. Tears the topology down and prints a results summary.

Tunable parameters live at the top of `run_experiment.sh`: `DURATION`,
`CC_ALGO` (`cubic`/`reno`), `DELAY_MS`, `BW_MBPS`, `QUEUE_PKTS`,
`OPT_TARGET_BW` (Mbps the attacker tries to steal via optimistic ACKing) and
`OPT_MULTIPLIER` (max optimistic lead as a multiple of the BDP).

Results are written to `/tmp/cse406/results/<scenario>_<cc>/`:
- `honest_throughput.csv` — timestamp, elapsed time, goodput (Mbps)
- `tcp_metrics.csv` — cwnd, ssthresh, RTT, retransmits, etc. **One row per
  flow per sample**, tagged with `peer_ip`/`peer_port`/`role` (`honest` vs
  `attacker`) so the two connections are never conflated.
- `queue_metrics.csv` — bottleneck queue backlog and drops

Logs are written to `/tmp/cse406/logs/`.

## Plotting results

```bash
python3 scripts/plot_results.py --results /tmp/cse406/results --output /tmp/cse406/results/plots
```

Produces goodput, cwnd, and queue-occupancy comparison charts (baseline vs.
attack vs. defense) plus a summary bar chart, saved as PNGs.

## Manual/interactive use

To drop into the Mininet CLI instead of running a full scenario (useful for
debugging the topology):

```bash
sudo python3 src/topology.py --cc cubic --delay 50 --bw 10 --queue 50 \
    --nginx-conf config/nginx.conf --cli
```

## Cleanup

`run_experiment.sh` cleans up after itself (`mn -c`, killing background
processes) via a trap on exit. If a run is interrupted uncleanly, reset
Mininet state manually with:

```bash
sudo mn -c
```

## Report

See [Design_Report_(2105158,2105160).pdf](Design_Report_(2105158,2105160).pdf)
for the full write-up: threat model, attack mechanics, defense design, and
experimental results.
