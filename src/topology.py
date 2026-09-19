#!/usr/bin/env python3

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

    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super().terminate()

def expose_namespaces(net):
    ns_dir = "/var/run/netns"
    os.makedirs(ns_dir, exist_ok=True)
    for host in net.hosts:
        src = f"/proc/{host.pid}/ns/net"
        dst = f"{ns_dir}/{host.name}"
        if os.path.islink(dst) or os.path.exists(dst):
            os.remove(dst)
        os.symlink(src, dst)
    info("*** Network namespaces exposed for ip netns exec\n")

def cleanup_namespaces(net):
    for host in net.hosts:
        dst = f"/var/run/netns/{host.name}"
        if os.path.islink(dst):
            os.remove(dst)

def build_topology(cc_algo="cubic", netem_delay=50, bw_mbps=10, queue_pkts=50,
                   fair_queue=False):
    net = Mininet(switch=OVSBridge, link=TCLink)

    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.3/24")
    h3 = net.addHost("h3", ip="10.0.0.2/24")

    r1 = net.addHost("r1", cls=LinuxRouter, ip="10.0.1.1/24")

    s1 = net.addSwitch("s1")

    net.addLink(h1, r1, intfName1="h1-eth0", intfName2="r1-eth0",
                params1={"ip": "10.0.1.2/24"},
                params2={"ip": "10.0.1.1/24"},
                bw=100)

    net.addLink(r1, s1, intfName1="r1-eth1", intfName2="s1-eth1",
                params1={"ip": "10.0.0.254/24"},
                bw=100)

    net.addLink(s1, h2, intfName2="h2-eth0", bw=100)
    net.addLink(s1, h3, intfName2="h3-eth0", bw=100)

    net.start()
    expose_namespaces(net)

    h1.cmd("ip addr flush dev h1-eth0")
    h1.cmd("ip addr add 10.0.1.2/24 dev h1-eth0")
    r1.cmd("ip addr flush dev r1-eth0")
    r1.cmd("ip addr add 10.0.1.1/24 dev r1-eth0")
    r1.cmd("ip addr flush dev r1-eth1")
    r1.cmd("ip addr add 10.0.0.254/24 dev r1-eth1")

    h1.cmd("ip route add 10.0.0.0/24 via 10.0.1.1")
    h2.cmd("ip route add 10.0.1.0/24 via 10.0.0.254")
    h3.cmd("ip route add 10.0.1.0/24 via 10.0.0.254")

    burst = max(bw_mbps * 1000 // 8, 1600)
    delay_pipe_pkts = int((bw_mbps * 1e6 / 8) * (netem_delay / 1000.0) / 1500)
    netem_limit = max(delay_pipe_pkts + queue_pkts, queue_pkts + 4)
    r1.cmd(f"tc qdisc del dev r1-eth1 root 2>/dev/null; true")
    r1.cmd(
        f"tc qdisc add dev r1-eth1 root handle 1: tbf "
        f"rate {bw_mbps}mbit burst {burst} limit {queue_pkts * 1500}"
    )
    if fair_queue:
        r1.cmd(
            f"tc qdisc add dev r1-eth1 parent 1: handle 10: netem "
            f"delay {netem_delay}ms limit 10240"
        )
        r1.cmd("tc qdisc add dev r1-eth1 parent 10: handle 100: fq_codel")
        info(f"*** Bottleneck: {bw_mbps} Mbps, {netem_delay} ms one-way delay, "
             f"FAIR per-flow queue (fq_codel) [DEFENSE]\n")
    else:
        r1.cmd(
            f"tc qdisc add dev r1-eth1 parent 1: handle 10: netem "
            f"delay {netem_delay}ms limit {netem_limit}"
        )
        info(f"*** Bottleneck: {bw_mbps} Mbps, {netem_delay} ms one-way delay, "
             f"drop-tail FIFO buffer {netem_limit} pkts "
             f"(~{queue_pkts}-pkt standing queue)\n")

    r1.cmd(f"tc qdisc del dev r1-eth0 root 2>/dev/null; true")
    r1.cmd(
        f"tc qdisc add dev r1-eth0 root handle 2: netem "
        f"delay {netem_delay}ms"
    )

    h1.cmd(f"sysctl -w net.ipv4.tcp_congestion_control={cc_algo}")
    h1.cmd("sysctl -w net.ipv4.tcp_no_metrics_save=1")
    h1.cmd("sysctl -w net.ipv4.tcp_moderate_rcvbuf=1")
    info(f"*** Server CC algorithm: {cc_algo}\n")

    h2.cmd(
        "iptables -A OUTPUT -p tcp --tcp-flags RST RST "
        "-s 10.0.0.3 -j DROP"
    )
    info("*** h2: kernel RST suppression enabled\n")

    return net

def start_nginx(host, config_path, video_path="/var/www/video.mp4"):
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
    parser.add_argument("--fair", action="store_true",
                        help="DEFENSE mode: use a per-flow fair queue "
                             "(fq_codel) at the bottleneck instead of a "
                             "drop-tail FIFO, neutralising the optimistic-ACK "
                             "attack")
    args = parser.parse_args()

    setLogLevel("info")
    net = build_topology(
        cc_algo=args.cc,
        netem_delay=args.delay,
        bw_mbps=args.bw,
        queue_pkts=args.queue,
        fair_queue=args.fair,
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
