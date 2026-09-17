#!/usr/bin/env python3
"""
topology.py — Mininet Dumbbell Testbed for TCP Optimistic-ACK Analysis
CSE 406: Computer Security Lab Project

Topology:
    h1 (NGINX server 10.0.0.1)
      |
     r1 (router / bottleneck shaper)
      |  tc tbf 10 Mbps, netem delay
     s1 (OVS switch, 100 Mbps links)
    /  \
   h2   h3
 (attacker  (honest
  10.0.0.3)  10.0.0.2)
"""

import argparse
import os
import sys
import time

from mininet.net import Mininet
from mininet.node import Node, OVSBridge
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class LinuxRouter(Node):
    """A node configured as a Linux IP router with forwarding enabled."""

    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super().terminate()


def expose_namespaces(net):
    """Symlink each host's netns into /var/run/netns/ so that
    'ip netns exec <name>' works from outside Mininet."""
    ns_dir = "/var/run/netns"
    os.makedirs(ns_dir, exist_ok=True)
    for host in net.hosts:
        src = f"/proc/{host.pid}/ns/net"
        dst = f"{ns_dir}/{host.name}"
        if os.path.exists(dst):
            os.remove(dst)
        os.symlink(src, dst)
    info("*** Network namespaces exposed for ip netns exec\n")


def cleanup_namespaces(net):
    """Remove the symlinks created by expose_namespaces."""
    for host in net.hosts:
        dst = f"/var/run/netns/{host.name}"
        if os.path.islink(dst):
            os.remove(dst)


def build_topology(cc_algo="cubic", netem_delay=50, bw_mbps=10, queue_pkts=50):
    """
    Build and return the Mininet network with the dumbbell topology.

    Parameters
    ----------
    cc_algo    : str   — TCP congestion control algorithm (cubic / reno)
    netem_delay: int   — One-way link delay in ms on the bottleneck
    bw_mbps    : int   — Bottleneck bandwidth in Mbps
    queue_pkts : int   — Bottleneck queue depth in packets
    """
    net = Mininet(switch=OVSBridge, link=TCLink)

    # --- Hosts ---
    h1 = net.addHost("h1", ip="10.0.0.1/24")       # NGINX media server
    h2 = net.addHost("h2", ip="10.0.0.3/24")        # Optimistic ACK generator
    h3 = net.addHost("h3", ip="10.0.0.2/24")        # Honest download client

    # --- Router (bottleneck shaper) ---
    r1 = net.addHost("r1", cls=LinuxRouter, ip="10.0.1.1/24")

    # --- Switch ---
    s1 = net.addSwitch("s1")

    # --- Links ---
    # h1 <-> r1: 100 Mbps, no shaping (the shaping is applied via tc later)
    net.addLink(h1, r1, intfName1="h1-eth0", intfName2="r1-eth0",
                params1={"ip": "10.0.1.2/24"},
                params2={"ip": "10.0.1.1/24"},
                bw=100)

    # r1 <-> s1: this is the bottleneck link — raw link is 100 Mbps,
    # but tc tbf will shape it to bw_mbps
    net.addLink(r1, s1, intfName1="r1-eth1", intfName2="s1-eth1",
                params1={"ip": "10.0.0.254/24"},
                bw=100)

    # s1 <-> h2, h3: 100 Mbps access links
    net.addLink(s1, h2, intfName2="h2-eth0", bw=100)
    net.addLink(s1, h3, intfName2="h3-eth0", bw=100)

    net.start()
    expose_namespaces(net)

    # ---------------------------------------------------------------
    # Routing: clients reach h1 via r1
    # ---------------------------------------------------------------
    h1.cmd("ip route add 10.0.0.0/24 via 10.0.1.1")
    h2.cmd("ip route add 10.0.1.0/24 via 10.0.0.254")
    h3.cmd("ip route add 10.0.1.0/24 via 10.0.0.254")

    # ---------------------------------------------------------------
    # Bottleneck shaping on r1-eth1 (toward clients)
    # ---------------------------------------------------------------
    burst = max(bw_mbps * 1000 // 8, 1600)  # bytes, at least one MTU
    r1.cmd(f"tc qdisc del dev r1-eth1 root 2>/dev/null; true")
    r1.cmd(
        f"tc qdisc add dev r1-eth1 root handle 1: tbf "
        f"rate {bw_mbps}mbit burst {burst} limit {queue_pkts * 1500}"
    )
    r1.cmd(
        f"tc qdisc add dev r1-eth1 parent 1: handle 10: netem "
        f"delay {netem_delay}ms"
    )
    info(f"*** Bottleneck: {bw_mbps} Mbps, {queue_pkts}-pkt queue, "
         f"{netem_delay} ms one-way delay\n")

    # Also shape the reverse direction (r1-eth0 toward h1) for RTT symmetry
    r1.cmd(f"tc qdisc del dev r1-eth0 root 2>/dev/null; true")
    r1.cmd(
        f"tc qdisc add dev r1-eth0 root handle 2: netem "
        f"delay {netem_delay}ms"
    )

    # ---------------------------------------------------------------
    # TCP congestion control on the server
    # ---------------------------------------------------------------
    h1.cmd(f"sysctl -w net.ipv4.tcp_congestion_control={cc_algo}")
    h1.cmd("sysctl -w net.ipv4.tcp_no_metrics_save=1")
    h1.cmd("sysctl -w net.ipv4.tcp_moderate_rcvbuf=1")
    info(f"*** Server CC algorithm: {cc_algo}\n")

    # ---------------------------------------------------------------
    # RST suppression on h2 so user-space Scapy ACKs work
    # ---------------------------------------------------------------
    h2.cmd(
        "iptables -A OUTPUT -p tcp --tcp-flags RST RST "
        "-s 10.0.0.3 -j DROP"
    )
    info("*** h2: kernel RST suppression enabled\n")

    return net


def start_nginx(host, config_path, video_path="/var/www/video.mp4"):
    """Start NGINX on the given host with the provided configuration."""
    host.cmd("mkdir -p /var/www")
    if not os.path.exists(video_path):
        host.cmd(f"dd if=/dev/urandom of={video_path} bs=1M count=200 2>/dev/null &")
        info("*** Generating 200 MB test video file...\n")
        host.cmd("wait")
    host.cmd(f"nginx -c {config_path}")
    time.sleep(1)
    info("*** NGINX started on h1:80\n")


def main():
    parser = argparse.ArgumentParser(
        description="Mininet dumbbell testbed for TCP optimistic-ACK analysis"
    )
    parser.add_argument("--cc", default="cubic", choices=["cubic", "reno"],
                        help="TCP congestion control algorithm (default: cubic)")
    parser.add_argument("--delay", type=int, default=50,
                        help="One-way bottleneck delay in ms (default: 50)")
    parser.add_argument("--bw", type=int, default=10,
                        help="Bottleneck bandwidth in Mbps (default: 10)")
    parser.add_argument("--queue", type=int, default=50,
                        help="Bottleneck queue depth in packets (default: 50)")
    parser.add_argument("--nginx-conf", default="/opt/cse406/config/nginx.conf",
                        help="Path to nginx.conf inside the Mininet host")
    parser.add_argument("--cli", action="store_true",
                        help="Drop into Mininet CLI after setup")
    args = parser.parse_args()

    setLogLevel("info")
    net = build_topology(
        cc_algo=args.cc,
        netem_delay=args.delay,
        bw_mbps=args.bw,
        queue_pkts=args.queue,
    )

    h1 = net.get("h1")
    start_nginx(h1, args.nginx_conf)

    if args.cli:
        CLI(net)
    else:
        info("*** Topology ready. Use run_experiment.sh to drive scenarios.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    info("*** Stopping network\n")
    h1.cmd("nginx -s stop 2>/dev/null; true")
    cleanup_namespaces(net)
    net.stop()


if __name__ == "__main__":
    main()
