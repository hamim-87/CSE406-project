// defense_inspector.c — eBPF/XDP Optimistic ACK Ingress Filter
// CSE 406: Computer Security Lab Project
//
// Attaches as an XDP program on the server's ingress interface (h1-eth0).
// Inspects every incoming TCP ACK and enforces two invariants:
//
//   1. Sent-bound:  ack_no <= snd_max   (cannot ACK unsent data)
//   2. Rate-bound:  Δack / Δt <= B_path + margin
//
// Non-compliant ACKs are dropped before reaching the kernel TCP stack,
// preventing the congestion window from being inflated by fabricated ACKs.
//
// Compile with:
//   clang -O2 -g -target bpf -c defense_inspector.c -o defense_inspector.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ──────────────────────────────────────────────────────────────────────
// Configuration constants (tunable)
// ──────────────────────────────────────────────────────────────────────
#define SERVER_PORT       80
#define MAX_FLOWS         1024

// Rate-bound parameters
// B_path = 10 Mbps = 1,250,000 bytes/sec.  We allow 50% margin.
#define BANDWIDTH_BPS     1250000ULL   // 10 Mbps in bytes/sec
#define RATE_MARGIN_PCT   50           // percent margin above path BW
#define RATE_LIMIT_BPS    (BANDWIDTH_BPS + BANDWIDTH_BPS * RATE_MARGIN_PCT / 100)

// Minimum time window for rate calculation (nanoseconds)
// Prevents division-by-tiny-interval false positives
#define MIN_RATE_WINDOW_NS  10000000ULL  // 10 ms

// ──────────────────────────────────────────────────────────────────────
// Per-flow state
// ──────────────────────────────────────────────────────────────────────
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct flow_state {
    __u32 snd_max;         // highest seq number we've sent (set by userspace)
    __u32 last_ack;        // last valid ACK number seen
    __u64 last_ack_ts;     // timestamp of last valid ACK (ns)
    __u64 ack_bytes_window;// bytes ACKed in current rate window
    __u64 window_start;    // start of current rate measurement window (ns)
    __u32 drops_sent;      // ACKs dropped: sent-bound violation
    __u32 drops_rate;      // ACKs dropped: rate-bound violation
    __u32 total_acks;      // total ACKs seen for this flow
};

// ──────────────────────────────────────────────────────────────────────
// BPF maps
// ──────────────────────────────────────────────────────────────────────

// Per-flow state tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flow_table SEC(".maps");

// Global counters for observability
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

enum counter_idx {
    CNT_TOTAL_PKTS   = 0,
    CNT_TCP_ACKS     = 1,
    CNT_DROPS_SENT   = 2,
    CNT_DROPS_RATE   = 3,
};

static __always_inline void inc_counter(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&counters, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// ──────────────────────────────────────────────────────────────────────
// Sequence number comparison (handles wraparound)
// ──────────────────────────────────────────────────────────────────────
static __always_inline int seq_before(__u32 a, __u32 b) {
    return (__s32)(a - b) < 0;
}

static __always_inline int seq_after(__u32 a, __u32 b) {
    return seq_before(b, a);
}

// ──────────────────────────────────────────────────────────────────────
// XDP program entry point
// ──────────────────────────────────────────────────────────────────────
SEC("xdp")
int xdp_ack_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_counter(CNT_TOTAL_PKTS);

    // --- Parse Ethernet ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- Parse IP ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // --- Parse TCP ---
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Only inspect packets destined to our server port (ACKs from clients)
    if (bpf_ntohs(tcp->dest) != SERVER_PORT)
        return XDP_PASS;

    // Only inspect ACK segments (ignore SYN, FIN-only, RST)
    if (!tcp->ack || tcp->syn || tcp->rst)
        return XDP_PASS;

    inc_counter(CNT_TCP_ACKS);

    // --- Build flow key ---
    struct flow_key key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    // --- Look up or create flow state ---
    struct flow_state *state = bpf_map_lookup_elem(&flow_table, &key);
    if (!state) {
        // New flow — initialize and allow (first ACK completes handshake)
        struct flow_state new_state = {
            .snd_max         = 0,
            .last_ack        = bpf_ntohl(tcp->ack_seq),
            .last_ack_ts     = bpf_ktime_get_ns(),
            .ack_bytes_window= 0,
            .window_start    = bpf_ktime_get_ns(),
            .drops_sent      = 0,
            .drops_rate      = 0,
            .total_acks      = 1,
        };
        bpf_map_update_elem(&flow_table, &key, &new_state, BPF_ANY);
        return XDP_PASS;
    }

    __u32 ack_no = bpf_ntohl(tcp->ack_seq);
    __u64 now_ns = bpf_ktime_get_ns();
    state->total_acks++;

    // ──────────────────────────────────────────────────────────────
    // CHECK 1: Sent-bound — ack_no must not exceed snd_max
    //
    // snd_max is updated by userspace (defense_loader.py) by reading
    // the kernel's TCP socket state. If snd_max is 0, the flow was
    // just created and we skip this check.
    // ──────────────────────────────────────────────────────────────
    if (state->snd_max != 0 && seq_after(ack_no, state->snd_max)) {
        state->drops_sent++;
        inc_counter(CNT_DROPS_SENT);
        return XDP_DROP;
    }

    // ──────────────────────────────────────────────────────────────
    // CHECK 2: Rate-bound — ACK advancement rate <= B_path + margin
    //
    // We track bytes ACKed within a sliding window. If the rate
    // exceeds the threshold, drop the ACK.
    // ──────────────────────────────────────────────────────────────
    __u32 ack_advance = 0;
    if (seq_after(ack_no, state->last_ack)) {
        ack_advance = ack_no - state->last_ack;
    }

    state->ack_bytes_window += ack_advance;
    __u64 window_elapsed = now_ns - state->window_start;

    if (window_elapsed >= MIN_RATE_WINDOW_NS) {
        // Calculate rate: bytes_in_window / time_in_seconds
        // To avoid floating point: compare bytes * 1e9 vs rate_limit * elapsed_ns
        __u64 bytes_scaled = state->ack_bytes_window * 1000000000ULL;
        __u64 limit_scaled = RATE_LIMIT_BPS * window_elapsed;

        if (bytes_scaled > limit_scaled) {
            state->drops_rate++;
            inc_counter(CNT_DROPS_RATE);
            return XDP_DROP;
        }

        // Reset window periodically (every ~100ms)
        if (window_elapsed >= 100000000ULL) {
            state->ack_bytes_window = 0;
            state->window_start = now_ns;
        }
    }

    // ACK is valid — update state and pass to kernel
    state->last_ack = ack_no;
    state->last_ack_ts = now_ns;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
