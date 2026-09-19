#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#define SERVER_PORT       80
#define MAX_FLOWS         1024

#define BANDWIDTH_BPS     1250000ULL
#define RATE_MARGIN_PCT   25
#define RATE_LIMIT_BPS    (BANDWIDTH_BPS + BANDWIDTH_BPS * RATE_MARGIN_PCT / 100)

#define BUCKET_MAX_BYTES  (128u * 1024u)

#define RTT_MIN_NS        90000000ULL
#define SNAP_RING_SIZE    32
#define SNAP_INTERVAL_NS  5000000ULL

struct flow_key {
    __u32 client_ip;
    __u32 server_ip;
    __u16 client_port;
    __u16 server_port;
};

struct flow_state {
    __u32 snd_max;
    __u32 last_ack;
    __u64 last_ack_ts;
    __u64 tokens;
    __u64 refill_ts;
    __u32 drops_sent;
    __u32 drops_rate;
    __u32 drops_time;
    __u32 total_acks;

    __u32 ring_seq[SNAP_RING_SIZE];
    __u64 ring_ts[SNAP_RING_SIZE];
    __u32 ring_head;
    __u64 last_snap_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 7);
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
    CNT_DROPS_TIME   = 6,
};

static __always_inline void inc_counter(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&counters, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline int seq_before(__u32 a, __u32 b) {
    return (__s32)(a - b) < 0;
}
static __always_inline int seq_after(__u32 a, __u32 b) {
    return seq_before(b, a);
}

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

    if (bpf_ntohs(tcp->source) != SERVER_PORT)
        return TC_ACT_OK;

    inc_counter(CNT_EGRESS_PKTS);

    __u32 tcp_hl = tcp->doff * 4;
    __u32 tot    = bpf_ntohs(ip->tot_len);
    __u32 hdrs   = ip_hl + tcp_hl;
    __u32 payload = tot > hdrs ? tot - hdrs : 0;

    __u32 seq_end = bpf_ntohl(tcp->seq) + payload;
    if (tcp->syn || tcp->fin)
        seq_end += 1;

    struct flow_key key = {
        .client_ip   = ip->daddr,
        .server_ip   = ip->saddr,
        .client_port = tcp->dest,
        .server_port = tcp->source,
    };

    __u64 now = bpf_ktime_get_ns();

    struct flow_state *st = bpf_map_lookup_elem(&flow_table, &key);
    if (!st) {
        struct flow_state ns = {
            .snd_max       = seq_end,
            .last_ack      = 0,
            .tokens        = BUCKET_MAX_BYTES,
            .refill_ts     = now,
            .ring_seq      = { seq_end },
            .ring_ts       = { now },
            .ring_head     = 1,
            .last_snap_ts  = now,
        };
        bpf_map_update_elem(&flow_table, &key, &ns, BPF_ANY);
        inc_counter(CNT_SND_UPDATES);
        return TC_ACT_OK;
    }

    if (seq_after(seq_end, st->snd_max)) {
        st->snd_max = seq_end;
        inc_counter(CNT_SND_UPDATES);
    }

    if (now - st->last_snap_ts >= SNAP_INTERVAL_NS) {
        __u32 h = st->ring_head & (SNAP_RING_SIZE - 1);
        st->ring_seq[h] = st->snd_max;
        st->ring_ts[h]  = now;
        st->ring_head   = h + 1;
        st->last_snap_ts = now;
    }
    return TC_ACT_OK;
}

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

    if (bpf_ntohs(tcp->dest) != SERVER_PORT)
        return XDP_PASS;

    if (!tcp->ack || tcp->syn || tcp->rst)
        return XDP_PASS;

    inc_counter(CNT_TCP_ACKS);

    struct flow_key key = {
        .client_ip   = ip->saddr,
        .server_ip   = ip->daddr,
        .client_port = tcp->source,
        .server_port = tcp->dest,
    };

    __u32 ack_no = bpf_ntohl(tcp->ack_seq);
    __u64 now_ns = bpf_ktime_get_ns();

    struct flow_state *state = bpf_map_lookup_elem(&flow_table, &key);
    if (!state) {

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

    if (state->snd_max != 0 && seq_after(ack_no, state->snd_max)) {
        state->drops_sent++;
        inc_counter(CNT_DROPS_SENT);
        return XDP_DROP;
    }

    if (now_ns > RTT_MIN_NS) {
        __u64 cutoff = now_ns - RTT_MIN_NS;
        __u64 best_ts = 0;
        __u32 snd_max_delayed = 0;
        #pragma clang loop unroll(full)
        for (int i = 0; i < SNAP_RING_SIZE; i++) {
            __u64 ts = state->ring_ts[i];
            if (ts != 0 && ts <= cutoff && ts >= best_ts) {
                best_ts = ts;
                snd_max_delayed = state->ring_seq[i];
            }
        }
        if (best_ts != 0 && seq_after(ack_no, snd_max_delayed)) {
            state->drops_time++;
            inc_counter(CNT_DROPS_TIME);
            return XDP_DROP;
        }
    }

    __u32 ack_advance = seq_after(ack_no, state->last_ack)
                        ? (ack_no - state->last_ack) : 0;

    __u64 dt = now_ns - state->refill_ts;
    __u64 refill = (RATE_LIMIT_BPS * dt) / 1000000000ULL;
    __u64 tokens = state->tokens + refill;
    if (tokens > BUCKET_MAX_BYTES)
        tokens = BUCKET_MAX_BYTES;
    state->refill_ts = now_ns;

    if (ack_advance > tokens) {
        state->tokens = tokens;
        state->drops_rate++;
        inc_counter(CNT_DROPS_RATE);
        return XDP_DROP;
    }

    state->tokens = tokens - ack_advance;
    state->last_ack = ack_no;
    state->last_ack_ts = now_ns;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
