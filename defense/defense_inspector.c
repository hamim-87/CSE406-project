// defense_inspector.c — eBPF Optimistic-ACK Filter (XDP ingress + TC egress)
// CSE 406: Computer Security Lab Project
//
// Two cooperating programs share one flow_table map:
//
//   * tc_snd_tracker  (SEC "tc",  attached to h1-eth0 EGRESS)
//       Watches the server's OUTGOING data segments and records, per flow,
//       the highest sequence number actually put on the wire (snd_max).
//       This is the absolute, always-correct source of snd_max — no fragile
//       userspace `ss`/bpftool sequence bookkeeping (which silently no-op'd
//       in the previous version and left the whole defense inert).
//
//   * xdp_ack_filter  (SEC "xdp", attached to h1-eth0 INGRESS)
//       Inspects every incoming client ACK and enforces two invariants:
//         1. Sent-bound:  ack_no <= snd_max            (cannot ACK unsent data)
//         2. Rate-bound:  ACK-advance rate <= B_path + margin  (token bucket)
//       Non-compliant ACKs are dropped before the kernel TCP stack sees them,
//       so fabricated/optimistic ACKs cannot inflate the congestion window.
//
// Because both programs are loaded from a single object with shared
// (pinned) maps, egress-observed snd_max is visible to the ingress filter.
//
// Compile with:
//   clang -O2 -g -target bpf -c defense_inspector.c -o defense_inspector.o

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Some header sets don't expose these to plain BPF C; define defensively so
// the object compiles on a stock clang/libbpf install.
#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

// ──────────────────────────────────────────────────────────────────────
// Configuration constants (tunable)
// ──────────────────────────────────────────────────────────────────────
#define SERVER_PORT       80
#define MAX_FLOWS         1024

// Rate-bound parameters.
// A flow sitting behind a B_path bottleneck physically cannot *receive*
// faster than B_path, so it must not be able to ACK faster than that either.
// We allow a modest margin for legitimate bursts. B_path = 10 Mbps.
#define BANDWIDTH_BPS     1250000ULL   // 10 Mbps in bytes/sec
#define RATE_MARGIN_PCT   25           // percent margin above path BW
#define RATE_LIMIT_BPS    (BANDWIDTH_BPS + BANDWIDTH_BPS * RATE_MARGIN_PCT / 100)

// Token-bucket burst allowance (bytes). Lets a well-behaved flow ACK a short
// burst (~one BDP) without penalty while still capping the sustained rate.
#define BUCKET_MAX_BYTES  (128u * 1024u)

// ──────────────────────────────────────────────────────────────────────
// Per-flow state.  Flow key is canonicalised to (client, server) in both
// directions so the ingress ACK and the egress data map to the same entry.
// ──────────────────────────────────────────────────────────────────────
struct flow_key {
    __u32 client_ip;
    __u32 server_ip;
    __u16 client_port;
    __u16 server_port;
};

struct flow_state {
    __u32 snd_max;         // highest seq the server has sent (from egress)
    __u32 last_ack;        // last ACK number we let through
    __u64 last_ack_ts;     // timestamp of last accepted ACK (ns)
    __u64 tokens;          // token-bucket balance, in bytes
    __u64 refill_ts;       // last token-bucket refill time (ns)
    __u32 drops_sent;      // ACKs dropped: sent-bound violation
    __u32 drops_rate;      // ACKs dropped: rate-bound violation
    __u32 total_acks;      // total ACKs seen for this flow
};

// ──────────────────────────────────────────────────────────────────────
// BPF maps (pinned by name so XDP + TC share one instance)
// ──────────────────────────────────────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} counters SEC(".maps");

enum counter_idx {
    CNT_TOTAL_PKTS   = 0,
    CNT_TCP_ACKS     = 1,
    CNT_DROPS_SENT   = 2,
    CNT_DROPS_RATE   = 3,
    CNT_EGRESS_PKTS  = 4,
    CNT_SND_UPDATES  = 5,
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
// TC EGRESS: learn snd_max from the server's outgoing data segments
// ──────────────────────────────────────────────────────────────────────
SEC("tc")
int tc_snd_tracker(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hl = ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ip_hl;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Only server -> client data (source port 80)
    if (bpf_ntohs(tcp->source) != SERVER_PORT)
        return TC_ACT_OK;

    inc_counter(CNT_EGRESS_PKTS);

    __u32 tcp_hl = tcp->doff * 4;
    __u32 tot    = bpf_ntohs(ip->tot_len);
    __u32 hdrs   = ip_hl + tcp_hl;
    __u32 payload = tot > hdrs ? tot - hdrs : 0;

    __u32 seq_end = bpf_ntohl(tcp->seq) + payload;
    if (tcp->syn || tcp->fin)
        seq_end += 1;                 // SYN/FIN each consume one seq number

    struct flow_key key = {
        .client_ip   = ip->daddr,     // egress: dst is the client
        .server_ip   = ip->saddr,
        .client_port = tcp->dest,
        .server_port = tcp->source,
    };

    struct flow_state *st = bpf_map_lookup_elem(&flow_table, &key);
    if (!st) {
        struct flow_state ns = {
            .snd_max    = seq_end,
            .last_ack   = 0,
            .tokens     = BUCKET_MAX_BYTES,
            .refill_ts  = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_table, &key, &ns, BPF_ANY);
        inc_counter(CNT_SND_UPDATES);
        return TC_ACT_OK;
    }

    if (seq_after(seq_end, st->snd_max)) {
        st->snd_max = seq_end;
        inc_counter(CNT_SND_UPDATES);
    }
    return TC_ACT_OK;
}

// ──────────────────────────────────────────────────────────────────────
// XDP INGRESS: enforce sent-bound + rate-bound on incoming client ACKs
// ──────────────────────────────────────────────────────────────────────
SEC("xdp")
int xdp_ack_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_counter(CNT_TOTAL_PKTS);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

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

    struct flow_key key = {
        .client_ip   = ip->saddr,     // ingress: src is the client
        .server_ip   = ip->daddr,
        .client_port = tcp->source,
        .server_port = tcp->dest,
    };

    __u32 ack_no = bpf_ntohl(tcp->ack_seq);
    __u64 now_ns = bpf_ktime_get_ns();

    struct flow_state *state = bpf_map_lookup_elem(&flow_table, &key);
    if (!state) {
        // Unseen by egress yet (e.g. the handshake ACK). Seed and allow.
        struct flow_state new_state = {
            .snd_max     = 0,
            .last_ack    = ack_no,
            .last_ack_ts = now_ns,
            .tokens      = BUCKET_MAX_BYTES,
            .refill_ts   = now_ns,
            .total_acks  = 1,
        };
        bpf_map_update_elem(&flow_table, &key, &new_state, BPF_ANY);
        return XDP_PASS;
    }

    state->total_acks++;

    // ── CHECK 1: Sent-bound — ack_no must not exceed snd_max ──────────
    // snd_max comes from the egress tracker. If it is still 0 the egress
    // hook has not observed this flow's data yet, so we skip the check
    // (fail open) rather than risk dropping the handshake.
    if (state->snd_max != 0 && seq_after(ack_no, state->snd_max)) {
        state->drops_sent++;
        inc_counter(CNT_DROPS_SENT);
        return XDP_DROP;
    }

    // ── CHECK 2: Rate-bound — token bucket on cumulative ACK advance ──
    // advance is measured from the last ACK we *accepted*, so dropping an
    // over-rate ACK genuinely holds snd_una back: the flow's ACK number can
    // only climb as fast as tokens refill (RATE_LIMIT_BPS). An optimistic
    // ACKer clocking the server above the path rate is throttled to it;
    // a legitimate flow (<= B_path) never runs out of tokens.
    __u32 ack_advance = seq_after(ack_no, state->last_ack)
                        ? (ack_no - state->last_ack) : 0;

    __u64 dt = now_ns - state->refill_ts;
    __u64 refill = (RATE_LIMIT_BPS * dt) / 1000000000ULL;
    __u64 tokens = state->tokens + refill;
    if (tokens > BUCKET_MAX_BYTES)
        tokens = BUCKET_MAX_BYTES;
    state->refill_ts = now_ns;

    if (ack_advance > tokens) {
        state->tokens = tokens;        // keep accumulating; drop this ACK
        state->drops_rate++;
        inc_counter(CNT_DROPS_RATE);
        return XDP_DROP;
    }

    // ACK is compliant — spend tokens, advance state, pass to the kernel.
    state->tokens = tokens - ack_advance;
    state->last_ack = ack_no;
    state->last_ack_ts = now_ns;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
