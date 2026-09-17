#!/usr/bin/env python3
"""
telemetry.py — TCP & Queue State Sampler (runs on h1: server)
CSE 406: Computer Security Lab Project

Periodically samples:
  1. Server TCP socket state via `ss -tin` — cwnd, ssthresh, RTT, retransmits
  2. Bottleneck queue occupancy via `tc -s qdisc` on the router interface

IMPORTANT — per-flow sampling
-----------------------------
The server holds *two* connections on port 80 at once during the attack
scenario: the honest client and the optimistic-ACK attacker. A single
`ss -ti sport = :80` therefore prints *both* flows, and grabbing "the first
match" mixes them into an uninterpretable trace. This sampler instead splits
the `ss` output into one block per connection, keyed by the peer address, and
writes **one CSV row per flow per sample** with a `peer_ip`/`peer_port`/`role`
tag. Downstream (plot_results.py) selects a flow by role, so the attacker's
cwnd is never confused with the honest client's.

Outputs time-series CSVs for offline analysis and plotting.
"""

import argparse
import csv
import logging
import os
import re
import signal
import subprocess
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Telem] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("telemetry")


# ──────────────────────────────────────────────────────────────────────
# ss -ti parser: extracts key TCP metrics from socket info output
# ──────────────────────────────────────────────────────────────────────
SS_FIELDS = {
    "cwnd":       re.compile(r"cwnd:(\d+)"),
    "ssthresh":   re.compile(r"ssthresh:(\d+)"),
    "rtt":        re.compile(r"rtt:(\d+(?:\.\d+)?)/"),       # rtt:value/var
    "rttvar":     re.compile(r"rtt:\d+(?:\.\d+)?/(\d+(?:\.\d+)?)"),
    "retrans":    re.compile(r"retrans:\d+/(\d+)"),          # total retransmits
    "bytes_sent": re.compile(r"bytes_sent:(\d+)"),
    "bytes_acked":re.compile(r"bytes_acked:(\d+)"),
    "send_rate":  re.compile(r"send (\d+(?:\.\d+)?[KMG]?bps)"),
    "unacked":    re.compile(r"unacked:(\d+)"),
    "snd_wnd":    re.compile(r"snd_wnd:(\d+)"),
}

# A connection header line from `ss -tin`, e.g.
#   ESTAB 0 0 10.0.1.2:80 10.0.0.3:44444
# Local (group 1/2) is the server (sport :80); Peer (group 3/4) is the client.
CONN_RE = re.compile(
    r"^ESTAB\s+\d+\s+\d+\s+"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)"
)


def parse_ss_output(raw):
    """Parse one `ss -ti` info block and return a dict of TCP metrics."""
    metrics = {}
    for field, pattern in SS_FIELDS.items():
        match = pattern.search(raw)
        metrics[field] = match.group(1) if match else ""
    return metrics


def parse_ss_flows(raw):
    """
    Split raw `ss -tin` output into one entry per established flow.

    Returns a list of dicts, each with the parsed SS_FIELDS plus
    ``peer_ip`` and ``peer_port`` (the *client* side of the connection).
    A connection's info block is every line after its ``ESTAB`` header up
    to the next header, so each flow is parsed in isolation — no cross-flow
    contamination.
    """
    flows = []
    cur_peer = None
    info_lines = []

    def flush():
        if cur_peer is not None:
            metrics = parse_ss_output("\n".join(info_lines))
            metrics["peer_ip"] = cur_peer[0]
            metrics["peer_port"] = cur_peer[1]
            flows.append(metrics)

    for line in raw.splitlines():
        conn = CONN_RE.match(line.strip())
        if conn:
            flush()                       # close out the previous flow
            cur_peer = (conn.group(3), conn.group(4))
            info_lines = []
        elif cur_peer is not None:
            info_lines.append(line)       # part of the current flow's block
    flush()                               # last flow
    return flows


# ──────────────────────────────────────────────────────────────────────
# tc -s qdisc parser: extracts queue stats
# ──────────────────────────────────────────────────────────────────────
TC_PATTERNS = {
    "sent_bytes":   re.compile(r"Sent (\d+) bytes"),
    "sent_pkts":    re.compile(r"Sent \d+ bytes (\d+) pkt"),
    "dropped":      re.compile(r"dropped (\d+)"),
    "overlimits":   re.compile(r"overlimits (\d+)"),
    "backlog_bytes":re.compile(r"backlog (\d+)b"),
    "backlog_pkts": re.compile(r"backlog \d+b (\d+)p"),
}


def parse_tc_output(raw):
    """Parse `tc -s qdisc` output and return queue statistics."""
    stats = {}
    for field, pattern in TC_PATTERNS.items():
        match = pattern.search(raw)
        stats[field] = match.group(1) if match else ""
    return stats


def classify_peer(peer_ip, attacker_ip, honest_ip):
    """Map a peer IP to a human-readable flow role."""
    if attacker_ip and peer_ip == attacker_ip:
        return "attacker"
    if honest_ip and peer_ip == honest_ip:
        return "honest"
    return "other"


# ──────────────────────────────────────────────────────────────────────
# Sampling loop
# ──────────────────────────────────────────────────────────────────────
def run_sampler(interval_ms, duration_s, tcp_csv_path, queue_csv_path,
                router_iface, remote_ns_cmd, attacker_ip, honest_ip):
    """
    Main sampling loop that runs every `interval_ms` milliseconds.

    Parameters
    ----------
    interval_ms    : int  — sampling period in milliseconds
    duration_s     : int  — total sampling duration (0 = indefinite)
    tcp_csv_path   : str  — output CSV for TCP metrics (one row per flow)
    queue_csv_path : str  — output CSV for queue metrics
    router_iface   : str  — interface name on router for tc stats
    remote_ns_cmd  : str  — prefix to run tc inside the router namespace
                            (e.g., "ip netns exec r1" or empty for same ns)
    attacker_ip    : str  — peer IP to label as the "attacker" flow
    honest_ip      : str  — peer IP to label as the "honest" flow
    """
    os.makedirs(os.path.dirname(tcp_csv_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(queue_csv_path) or ".", exist_ok=True)

    tcp_fields = (["timestamp", "elapsed_s", "peer_ip", "peer_port", "role"]
                  + list(SS_FIELDS.keys()))
    queue_fields = ["timestamp", "elapsed_s"] + list(TC_PATTERNS.keys())

    tcp_file = open(tcp_csv_path, "w", newline="")
    queue_file = open(queue_csv_path, "w", newline="")
    tcp_writer = csv.DictWriter(tcp_file, fieldnames=tcp_fields)
    queue_writer = csv.DictWriter(queue_file, fieldnames=queue_fields)
    tcp_writer.writeheader()
    queue_writer.writeheader()

    interval_s = interval_ms / 1000.0
    start = time.monotonic()
    running = True

    def stop_handler(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    log.info("Sampling every %d ms → %s, %s", interval_ms, tcp_csv_path, queue_csv_path)
    log.info("Flow roles: attacker=%s honest=%s",
             attacker_ip or "<none>", honest_ip or "<none>")
    sample_count = 0

    try:
        while running:
            now = time.monotonic()
            elapsed = now - start
            if duration_s > 0 and elapsed >= duration_s:
                break

            ts = f"{now:.3f}"
            el = f"{elapsed:.3f}"

            # --- TCP state from ss: one row per established flow ---
            try:
                ss_raw = subprocess.check_output(
                    ["ss", "-tin", "state", "established", "sport", "=", ":80"],
                    text=True, timeout=2
                )
                flows = parse_ss_flows(ss_raw)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                flows = []

            sampled = []
            for metrics in flows:
                role = classify_peer(metrics["peer_ip"], attacker_ip, honest_ip)
                row = {"timestamp": ts, "elapsed_s": el, "role": role}
                row.update(metrics)
                tcp_writer.writerow(row)
                sampled.append((role, metrics))

            # --- Queue state from tc ---
            try:
                tc_cmd = f"{remote_ns_cmd} tc -s qdisc show dev {router_iface}".split()
                tc_raw = subprocess.check_output(tc_cmd, text=True, timeout=2)
                queue_stats = parse_tc_output(tc_raw)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                queue_stats = {k: "" for k in TC_PATTERNS}

            qrow = {"timestamp": ts, "elapsed_s": el}
            qrow.update(queue_stats)
            queue_writer.writerow(qrow)

            sample_count += 1
            if sample_count % max(1, 5000 // interval_ms) == 0:
                tcp_file.flush()
                queue_file.flush()
                # Summarize each flow's cwnd rather than an arbitrary one.
                flow_summary = " ".join(
                    f"{role}:cwnd={m.get('cwnd', '?') or '-'}"
                    for role, m in sampled
                ) or "no-flows"
                log.info("Samples: %d | %s | backlog=%s pkts dropped=%s",
                         sample_count, flow_summary,
                         queue_stats.get("backlog_pkts", "?"),
                         queue_stats.get("dropped", "?"))

            # Tight sleep to honor the sampling interval
            sleep_until = now + interval_s
            remaining = sleep_until - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)

    finally:
        tcp_file.close()
        queue_file.close()
        log.info("Sampling complete: %d samples in %.1f s",
                 sample_count, time.monotonic() - start)


def main():
    parser = argparse.ArgumentParser(
        description="TCP & queue telemetry sampler for CSE 406 lab"
    )
    parser.add_argument("--interval", type=int, default=100,
                        help="Sampling interval in ms (default: 100)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Sampling duration in seconds (0 = indefinite)")
    parser.add_argument("--tcp-csv", default="/tmp/cse406/results/tcp_metrics.csv",
                        help="Output CSV for TCP metrics (one row per flow)")
    parser.add_argument("--queue-csv", default="/tmp/cse406/results/queue_metrics.csv",
                        help="Output CSV for queue metrics")
    parser.add_argument("--router-iface", default="r1-eth1",
                        help="Router interface to query tc stats from")
    parser.add_argument("--ns-cmd", default="",
                        help="Namespace exec prefix for tc commands "
                             "(e.g., 'ip netns exec r1')")
    parser.add_argument("--attacker-ip", default="10.0.0.3",
                        help="Peer IP to tag as the attacker flow")
    parser.add_argument("--honest-ip", default="10.0.0.2",
                        help="Peer IP to tag as the honest-client flow")
    args = parser.parse_args()

    run_sampler(
        interval_ms=args.interval,
        duration_s=args.duration,
        tcp_csv_path=args.tcp_csv,
        queue_csv_path=args.queue_csv,
        router_iface=args.router_iface,
        remote_ns_cmd=args.ns_cmd,
        attacker_ip=args.attacker_ip,
        honest_ip=args.honest_ip,
    )


if __name__ == "__main__":
    main()
