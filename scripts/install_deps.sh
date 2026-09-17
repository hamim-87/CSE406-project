#!/usr/bin/env bash
# install_deps.sh — Install all dependencies for the CSE 406 lab
# Run as root on Ubuntu 20.04+ / Debian 11+

set -euo pipefail

echo "=== CSE 406 Lab Dependencies ==="

apt-get update

# Mininet and network emulation
apt-get install -y mininet openvswitch-switch

# Python packages
apt-get install -y python3 python3-pip python3-scapy
pip3 install matplotlib

# NGINX
apt-get install -y nginx

# Traffic control / iproute2
apt-get install -y iproute2

# eBPF toolchain
apt-get install -y clang llvm libelf-dev \
    linux-headers-$(uname -r) \
    libbpf-dev bpftool

# Useful utilities
apt-get install -y tcpdump iperf3 net-tools curl

echo ""
echo "=== All dependencies installed ==="
echo "Verify with:"
echo "  mn --version"
echo "  python3 -c 'from scapy.all import IP; print(\"Scapy OK\")'"
echo "  nginx -v"
echo "  clang --version"
echo "  bpftool version"
