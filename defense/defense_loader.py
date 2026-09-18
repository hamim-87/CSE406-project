#!/usr/bin/env python3
"""
defense_loader.py — eBPF Program Loader (XDP ingress + TC egress)
CSE 406: Computer Security Lab Project

Loads defense_inspector.o and attaches both of its programs to the server's
interface so they share one flow_table map:

  * xdp_ack_filter  → XDP on ingress  (filters incoming client ACKs)
  * tc_snd_tracker  → TC clsact egress (learns snd_max from outgoing data)

snd_max is now maintained entirely in the datapath by the egress program.
The previous version tried to push snd_max in from userspace by parsing `ss`
and writing a *partial* value with `bpftool map update` — the byte count
never matched the 48-byte flow_state, so every update silently failed and the
sent-bound check saw snd_max == 0 forever (the defense did nothing). That
whole path is gone.

Map sharing across the two hooks is achieved by loading the object once with
`bpftool prog loadall ... pinmaps <dir>` (maps are declared LIBBPF_PIN_BY_NAME
in the C), then attaching each pinned program. This is the piece that is
easy to get wrong on a fresh VM, so it is done explicitly and checked.
"""

import argparse
import json
import logging
import os
import signal
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

BPFFS = "/sys/fs/bpf"
PIN_DIR = "/sys/fs/bpf/cse406_defense"
XDP_PROG = "xdp_ack_filter"      # must match SEC/func name in the .c (<=15 chars)
TC_PROG = "tc_snd_tracker"       # must match SEC/func name in the .c (<=15 chars)

COUNTER_LABELS = [
    "total_pkts", "tcp_acks", "drops_sent_bound",
    "drops_rate_bound", "egress_pkts", "snd_max_updates",
    "drops_time_bound",
]


def run(cmd, check=True, quiet=False):
    """Run a command, logging failures. Returns CompletedProcess."""
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0 and not quiet:
        log.error("cmd failed (%d): %s", res.returncode, " ".join(cmd))
        if res.stderr.strip():
            log.error("  stderr: %s", res.stderr.strip())
    if check and res.returncode != 0:
        sys.exit(1)
    return res


def ensure_bpffs():
    """Make sure the BPF filesystem is mounted (needed for map pinning)."""
    if not os.path.ismount(BPFFS):
        os.makedirs(BPFFS, exist_ok=True)
        run(["mount", "-t", "bpf", "none", BPFFS])
        log.info("Mounted bpffs at %s", BPFFS)


def load_and_attach(iface, obj_path, xdp_mode):
    """Load both programs with shared maps and attach them to `iface`."""
    if not os.path.exists(obj_path):
        log.error("BPF object not found: %s (compile it first)", obj_path)
        sys.exit(1)

    ensure_bpffs()

    # Clean any prior state so a re-run starts fresh.
    detach(iface, quiet=True)

    # Load the whole object once; pin every program and map under PIN_DIR.
    # Sharing the pinned maps is what lets the egress tracker's snd_max reach
    # the ingress filter.
    run(["bpftool", "prog", "loadall", obj_path, PIN_DIR, "pinmaps", PIN_DIR])
    log.info("Loaded %s (progs + maps pinned under %s)", obj_path, PIN_DIR)

    xdp_pin = os.path.join(PIN_DIR, XDP_PROG)
    tc_pin = os.path.join(PIN_DIR, TC_PROG)
    for p in (xdp_pin, tc_pin):
        if not os.path.exists(p):
            log.error("Expected pinned program missing: %s", p)
            log.error("  (check the SEC/function names in defense_inspector.c)")
            detach(iface, quiet=True)
            sys.exit(1)

    # Attach XDP (ingress) from the pinned program.
    run(["ip", "link", "set", "dev", iface, f"xdp{xdp_mode}",
         "pinned", xdp_pin])
    log.info("XDP filter attached on %s ingress (mode=%s)", iface, xdp_mode)

    # Attach TC (egress) from the pinned program via a clsact qdisc.
    run(["tc", "qdisc", "add", "dev", iface, "clsact"], check=False, quiet=True)
    run(["tc", "filter", "add", "dev", iface, "egress",
         "bpf", "da", "pinned", tc_pin])
    log.info("TC snd_max tracker attached on %s egress", iface)


def detach(iface, quiet=False):
    """Remove both programs and all pinned state."""
    subprocess.run(["ip", "link", "set", "dev", iface, "xdpgeneric", "off"],
                   capture_output=True)
    subprocess.run(["ip", "link", "set", "dev", iface, "xdp", "off"],
                   capture_output=True)
    # Deleting the clsact qdisc removes the egress filter with it.
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "clsact"],
                   capture_output=True)
    subprocess.run(["rm", "-rf", PIN_DIR], capture_output=True)
    if not quiet:
        log.info("Detached XDP/TC programs and removed pins from %s", iface)


def read_counters():
    """Read the global counters from the pinned BPF array map."""
    values = {}
    pin = os.path.join(PIN_DIR, "counters")
    try:
        raw = subprocess.check_output(
            ["bpftool", "map", "dump", "pinned", pin, "-j"],
            text=True, timeout=2
        )
        for entry in json.loads(raw):
            key_bytes = entry.get("key", [])
            val_bytes = entry.get("value", [])
            if len(key_bytes) >= 4 and len(val_bytes) >= 8:
                idx = struct.unpack_from("<I", bytes(key_bytes))[0]
                val = struct.unpack_from("<Q", bytes(val_bytes))[0]
                if idx < len(COUNTER_LABELS):
                    values[COUNTER_LABELS[idx]] = val
    except Exception:
        pass
    return values


def count_flows():
    """Return the number of entries currently in the flow_table map."""
    pin = os.path.join(PIN_DIR, "flow_table")
    try:
        raw = subprocess.check_output(
            ["bpftool", "map", "dump", "pinned", pin, "-j"],
            text=True, timeout=2
        )
        return len(json.loads(raw))
    except Exception:
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Load XDP+TC optimistic-ACK filter and report stats"
    )
    parser.add_argument("--iface", default="h1-eth0",
                        help="Interface to attach programs to (default: h1-eth0)")
    parser.add_argument("--obj", default="/opt/cse406/defense/defense_inspector.o",
                        help="Path to compiled BPF object file")
    parser.add_argument("--mode", default="generic",
                        choices=["generic", "skb", "drv", "hw"],
                        help="XDP attach mode (default: generic, for veth)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Stats print interval in seconds (default: 1.0)")
    parser.add_argument("--unload", action="store_true",
                        help="Detach programs and exit")
    args = parser.parse_args()

    # `ip link set ... xdpgeneric` is the veth-friendly generic mode; accept
    # the old "skb" spelling as an alias for it.
    xdp_mode = "generic" if args.mode in ("generic", "skb") else args.mode

    if args.unload:
        detach(args.iface)
        return

    load_and_attach(args.iface, args.obj, xdp_mode)

    running = True
    def stop_handler(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    log.info("Entering stats loop (every %.1fs). Ctrl-C to stop.", args.interval)
    tick = 0
    try:
        while running:
            tick += 1
            if tick % max(1, int(round(1.0 / args.interval))) == 0 or args.interval >= 1:
                stats = read_counters()
                log.info("acks=%s | dropped time-bound=%s sent-bound=%s "
                         "rate-bound=%s | egress=%s snd_max_upd=%s | flows=%d",
                         stats.get("tcp_acks", "?"),
                         stats.get("drops_time_bound", "?"),
                         stats.get("drops_sent_bound", "?"),
                         stats.get("drops_rate_bound", "?"),
                         stats.get("egress_pkts", "?"),
                         stats.get("snd_max_updates", "?"),
                         count_flows())
            time.sleep(args.interval)
    finally:
        detach(args.iface)
        log.info("Defense module stopped cleanly")


if __name__ == "__main__":
    main()
