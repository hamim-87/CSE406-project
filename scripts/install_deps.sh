#!/usr/bin/env bash

set -euo pipefail

echo "=== CSE 406 Lab Dependencies ==="

apt-get update

apt-get install -y mininet openvswitch-switch

apt-get install -y python3 python3-pip python3-scapy python3-matplotlib

apt-get install -y nginx

apt-get install -y iproute2

apt-get install -y clang llvm libelf-dev \
    linux-headers-$(uname -r) \
    libbpf-dev \
    linux-tools-common linux-tools-generic "linux-tools-$(uname -r)"

apt-get install -y tcpdump iperf3 net-tools curl

echo ""
echo "=== All dependencies installed ==="
echo "Verify with:"
echo "  mn --version"
echo "  python3 -c 'from scapy.all import IP; print(\"Scapy OK\")'"
echo "  nginx -v"
echo "  clang --version"
echo "  bpftool version"
