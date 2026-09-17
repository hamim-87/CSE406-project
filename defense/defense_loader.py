#!/usr/bin/env python3
"""
defense_loader.py — eBPF/XDP Program Loader & snd_max Updater
CSE 406: Computer Security Lab Project

Loads the compiled XDP program (defense_inspector.o) onto the server's
ingress interface and periodically updates per-flow snd_max values by
reading the kernel's TCP socket state via `ss`.

Also prints live statistics from the BPF counters map.
"""

import argparse
import ctypes
import logging
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Defense] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("defense_loader")


# ──────────────────────────────────────────────────────────────────────
# BPF map interaction via bpftool (simpler than ctypes for a lab)
# ──────────────────────────────────────────────────────────────────────
def load_xdp(iface, obj_path, mode="skb"):
    """Attach the XDP program to the given interface."""
    # Remove any existing XDP program
    subprocess.run(["ip", "link", "set", "dev", iface, "xdp", "off"],
                   capture_output=True)

    cmd = ["ip", "link", "set", "dev", iface, f"xdp{mode}", "obj",
           obj_path, "sec", "xdp"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log.error("Failed to load XDP program: %s", result.stderr)
        sys.exit(1)
    log.info("XDP program loaded on %s (mode=%s)", iface, mode)


def unload_xdp(iface):
    """Detach any XDP program from the interface."""
    subprocess.run(["ip", "link", "set", "dev", iface, "xdp", "off"],
                   capture_output=True)
    log.info("XDP program unloaded from %s", iface)


def read_counters():
    """Read the global counters from the BPF array map."""
    labels = ["total_pkts", "tcp_acks", "drops_sent_bound", "drops_rate_bound"]
    values = {}
    try:
        raw = subprocess.check_output(
            ["bpftool", "map", "dump", "name", "counters", "-j"],
            text=True, timeout=2
        )
        import json
        entries = json.loads(raw)
        for entry in entries:
            key_bytes = entry.get("key", [])
            val_bytes = entry.get("value", [])
            if len(key_bytes) >= 4 and len(val_bytes) >= 8:
                idx = struct.unpack_from("<I", bytes(key_bytes))[0]
                val = struct.unpack_from("<Q", bytes(val_bytes))[0]
                if idx < len(labels):
                    values[labels[idx]] = val
    except Exception:
        pass
    return values


def get_tcp_snd_max():
    """
    Parse `ss -ti` to extract per-flow (src:port → dst:port) snd_max.
    snd_max ≈ bytes_sent value from ss, converted to absolute seq.
    For simplicity, we use bytes_sent + ISN as an approximation.

    Returns dict: {(src_ip, src_port, dst_ip, dst_port): snd_max_estimate}
    """
    flows = {}
    try:
        raw = subprocess.check_output(
            ["ss", "-ti", "state", "established", "sport", "=", ":80"],
            text=True, timeout=2
        )
        # Parse connection lines and their info blocks
        lines = raw.strip().split("\n")
        current_flow = None
        for line in lines:
            # Connection line: "ESTAB 0 12345 10.0.0.1:80 10.0.0.3:44444"
            conn_match = re.match(
                r"\s*ESTAB\s+\d+\s+(\d+)\s+"
                r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+"
                r"(\d+\.\d+\.\d+\.\d+):(\d+)",
                line
            )
            if conn_match:
                send_q = int(conn_match.group(1))
                src_ip = conn_match.group(2)
                src_port = int(conn_match.group(3))
                dst_ip = conn_match.group(4)
                dst_port = int(conn_match.group(5))
                current_flow = (dst_ip, dst_port, src_ip, src_port)
                continue

            # Info line with bytes_sent
            if current_flow:
                bs_match = re.search(r"bytes_sent:(\d+)", line)
                ba_match = re.search(r"bytes_acked:(\d+)", line)
                if bs_match:
                    bytes_sent = int(bs_match.group(1))
                    flows[current_flow] = bytes_sent
                current_flow = None

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    return flows


def update_flow_snd_max(flows_data):
    """
    Update the snd_max field in the BPF flow_table map for each active flow.
    Uses bpftool to write into the map.
    """
    for (src_ip, src_port, dst_ip, dst_port), snd_max in flows_data.items():
        try:
            # Pack the flow key: src_ip(4) dst_ip(4) src_port(2) dst_port(2)
            src_bytes = socket.inet_aton(src_ip)
            dst_bytes = socket.inet_aton(dst_ip)
            key_hex = " ".join(f"0x{b:02x}" for b in (
                src_bytes + dst_bytes +
                struct.pack("!HH", src_port, dst_port)
            ))

            # Read current state
            result = subprocess.run(
                ["bpftool", "map", "lookup", "name", "flow_table",
                 "key", "hex"] + key_hex.split(),
                capture_output=True, text=True, timeout=2
            )
            if result.returncode != 0:
                continue

            # Update snd_max (first 4 bytes of flow_state value)
            snd_max_bytes = struct.pack("<I", snd_max & 0xFFFFFFFF)
            snd_max_hex = " ".join(f"0x{b:02x}" for b in snd_max_bytes)

            # We need to read-modify-write; for lab purposes, we update
            # just the snd_max field using bpftool
            subprocess.run(
                ["bpftool", "map", "update", "name", "flow_table",
                 "key", "hex"] + key_hex.split() +
                ["value", "hex"] + snd_max_hex.split(),
                capture_output=True, timeout=2
            )
        except Exception as e:
            log.debug("Error updating flow %s:%d → %s:%d: %s",
                      src_ip, src_port, dst_ip, dst_port, e)


# ──────────────────────────────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Load XDP ACK filter and maintain per-flow snd_max"
    )
    parser.add_argument("--iface", default="h1-eth0",
                        help="Interface to attach XDP program (default: h1-eth0)")
    parser.add_argument("--obj", default="/opt/cse406/defense/defense_inspector.o",
                        help="Path to compiled BPF object file")
    parser.add_argument("--mode", default="skb", choices=["skb", "drv", "hw"],
                        help="XDP attach mode (default: skb for veth)")
    parser.add_argument("--interval", type=float, default=0.5,
                        help="snd_max update interval in seconds (default: 0.5)")
    parser.add_argument("--unload", action="store_true",
                        help="Unload XDP program and exit")
    args = parser.parse_args()

    if args.unload:
        unload_xdp(args.iface)
        return

    load_xdp(args.iface, args.obj, args.mode)

    running = True
    def stop_handler(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    log.info("Entering snd_max update loop (every %.1fs)", args.interval)
    update_count = 0

    try:
        while running:
            # Update snd_max for all active flows
            flows = get_tcp_snd_max()
            if flows:
                update_flow_snd_max(flows)
            update_count += 1

            # Print stats every 10 iterations
            if update_count % 10 == 0:
                stats = read_counters()
                log.info("Stats: pkts=%s acks=%s drop_sent=%s drop_rate=%s "
                         "| active_flows=%d",
                         stats.get("total_pkts", "?"),
                         stats.get("tcp_acks", "?"),
                         stats.get("drops_sent_bound", "?"),
                         stats.get("drops_rate_bound", "?"),
                         len(flows))

            time.sleep(args.interval)

    finally:
        unload_xdp(args.iface)
        log.info("Defense module stopped cleanly")


if __name__ == "__main__":
    main()
