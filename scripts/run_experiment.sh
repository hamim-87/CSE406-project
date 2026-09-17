#!/usr/bin/env bash
# run_experiment.sh — Orchestrates baseline and attack experiments
# CSE 406: Computer Security Lab Project
#
# Usage:
#   sudo ./scripts/run_experiment.sh [baseline|attack|defense|all]
#
# Prerequisites:
#   - Mininet, Scapy, NGINX, bpftool, clang (for BPF) installed
#   - Run as root (Mininet requires it)

set -euo pipefail

# ──────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${PROJECT_DIR}/src"
DEFENSE_DIR="${PROJECT_DIR}/defense"
CONFIG_DIR="${PROJECT_DIR}/config"
RESULTS_DIR="/tmp/cse406/results"
LOGS_DIR="/tmp/cse406/logs"
DURATION=60          # seconds per scenario
CC_ALGO="cubic"      # congestion control: cubic or reno
DELAY_MS=50          # one-way bottleneck delay
BW_MBPS=10           # bottleneck bandwidth
QUEUE_PKTS=50        # bottleneck queue depth

# Optimistic ACK parameters
OPT_DELTA=14600      # bytes per ACK (10 × MSS)
OPT_RATE=200         # ACKs/second

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ──────────────────────────────────────────────────────────────────
# Pre-flight checks
# ──────────────────────────────────────────────────────────────────
preflight() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (Mininet requirement)"
        exit 1
    fi

    for cmd in mn python3 nginx ss tc; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done

    mkdir -p "$RESULTS_DIR" "$LOGS_DIR"
    log_info "Results directory: $RESULTS_DIR"
    log_info "Logs directory:    $LOGS_DIR"
}

# ──────────────────────────────────────────────────────────────────
# Generate test video file if missing
# ──────────────────────────────────────────────────────────────────
ensure_video() {
    if [[ ! -f /var/www/video.mp4 ]]; then
        log_step "Generating 200 MB test video file..."
        mkdir -p /var/www
        dd if=/dev/urandom of=/var/www/video.mp4 bs=1M count=200 status=progress 2>/dev/null
        log_info "Test file created: /var/www/video.mp4"
    fi
}

# ──────────────────────────────────────────────────────────────────
# Compile BPF defense module
# ──────────────────────────────────────────────────────────────────
compile_bpf() {
    log_step "Compiling eBPF defense module..."
    if ! command -v clang &>/dev/null; then
        log_warn "clang not found — skipping BPF compilation"
        return 1
    fi
    clang -O2 -g -target bpf \
        -I/usr/include/$(uname -m)-linux-gnu \
        -c "${DEFENSE_DIR}/defense_inspector.c" \
        -o "${DEFENSE_DIR}/defense_inspector.o"
    log_info "BPF object compiled: ${DEFENSE_DIR}/defense_inspector.o"
}

# ──────────────────────────────────────────────────────────────────
# Cleanup function
# ──────────────────────────────────────────────────────────────────
cleanup() {
    log_step "Cleaning up..."
    # Kill any background processes we started
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    # Stop Mininet
    mn -c 2>/dev/null || true
    log_info "Cleanup complete"
}
trap cleanup EXIT

# ──────────────────────────────────────────────────────────────────
# Scenario: BASELINE (honest client only, no attack)
# ──────────────────────────────────────────────────────────────────
run_baseline() {
    log_step "═══ SCENARIO: BASELINE (no attack) ═══"
    local tag="baseline_${CC_ALGO}"

    # Start Mininet topology in background
    python3 "${SRC_DIR}/topology.py" \
        --cc "$CC_ALGO" --delay "$DELAY_MS" --bw "$BW_MBPS" --queue "$QUEUE_PKTS" \
        --nginx-conf "${CONFIG_DIR}/nginx.conf" &
    local topo_pid=$!
    sleep 5  # wait for topology + NGINX

    # Start telemetry on h1
    log_step "Starting telemetry sampler..."

    # Use ip netns exec to run commands on Mininet hosts
    python3 -c "
import time, subprocess, os, sys
sys.path.insert(0, '${SRC_DIR}')

# We connect to the running Mininet via its API
# For the lab, we run components directly in the Mininet namespace
os.system('mkdir -p ${RESULTS_DIR}/${tag}')

# Run telemetry on h1
subprocess.Popen([
    'ip', 'netns', 'exec', 'h1',
    'python3', '${SRC_DIR}/telemetry.py',
    '--interval', '100',
    '--duration', '${DURATION}',
    '--tcp-csv', '${RESULTS_DIR}/${tag}/tcp_metrics.csv',
    '--queue-csv', '${RESULTS_DIR}/${tag}/queue_metrics.csv',
    '--router-iface', 'r1-eth1',
    '--ns-cmd', 'ip netns exec r1',
])

# Run honest client on h3
time.sleep(2)
subprocess.Popen([
    'ip', 'netns', 'exec', 'h3',
    'python3', '${SRC_DIR}/honest_client.py',
    '--url', 'http://10.0.1.2/video.mp4',
    '--output', '${RESULTS_DIR}/${tag}/honest_throughput.csv',
    '--duration', '${DURATION}',
])

time.sleep(${DURATION} + 5)
" 2>&1 | tee "${LOGS_DIR}/${tag}.log" || true

    kill $topo_pid 2>/dev/null || true
    wait $topo_pid 2>/dev/null || true
    mn -c 2>/dev/null || true

    log_info "Baseline results saved to ${RESULTS_DIR}/${tag}/"
}

# ──────────────────────────────────────────────────────────────────
# Scenario: ATTACK (optimistic ACK + honest client)
# ──────────────────────────────────────────────────────────────────
run_attack() {
    log_step "═══ SCENARIO: ATTACK (optimistic ACKing) ═══"
    local tag="attack_${CC_ALGO}"

    python3 "${SRC_DIR}/topology.py" \
        --cc "$CC_ALGO" --delay "$DELAY_MS" --bw "$BW_MBPS" --queue "$QUEUE_PKTS" \
        --nginx-conf "${CONFIG_DIR}/nginx.conf" &
    local topo_pid=$!
    sleep 5

    python3 -c "
import time, subprocess, os
os.makedirs('${RESULTS_DIR}/${tag}', exist_ok=True)

# Telemetry on h1
telem = subprocess.Popen([
    'ip', 'netns', 'exec', 'h1',
    'python3', '${SRC_DIR}/telemetry.py',
    '--interval', '100',
    '--duration', '${DURATION}',
    '--tcp-csv', '${RESULTS_DIR}/${tag}/tcp_metrics.csv',
    '--queue-csv', '${RESULTS_DIR}/${tag}/queue_metrics.csv',
    '--router-iface', 'r1-eth1',
    '--ns-cmd', 'ip netns exec r1',
])

time.sleep(2)

# Honest client on h3 (starts first to establish baseline flow)
honest = subprocess.Popen([
    'ip', 'netns', 'exec', 'h3',
    'python3', '${SRC_DIR}/honest_client.py',
    '--url', 'http://10.0.1.2/video.mp4',
    '--output', '${RESULTS_DIR}/${tag}/honest_throughput.csv',
    '--duration', '${DURATION}',
])

time.sleep(5)  # let honest flow stabilize

# Optimistic ACK attacker on h2
attacker = subprocess.Popen([
    'ip', 'netns', 'exec', 'h2',
    'python3', '${SRC_DIR}/optimistic_client.py',
    '--server', '10.0.1.2',
    '--port', '80',
    '--delta', '${OPT_DELTA}',
    '--rate', '${OPT_RATE}',
    '--duration', str(${DURATION} - 10),
])

time.sleep(${DURATION} + 5)

for p in [telem, honest, attacker]:
    try:
        p.terminate()
        p.wait(timeout=5)
    except:
        p.kill()
" 2>&1 | tee "${LOGS_DIR}/${tag}.log" || true

    kill $topo_pid 2>/dev/null || true
    wait $topo_pid 2>/dev/null || true
    mn -c 2>/dev/null || true

    log_info "Attack results saved to ${RESULTS_DIR}/${tag}/"
}

# ──────────────────────────────────────────────────────────────────
# Scenario: DEFENSE (attack + XDP filter active)
# ──────────────────────────────────────────────────────────────────
run_defense() {
    log_step "═══ SCENARIO: DEFENSE (XDP filter active) ═══"
    local tag="defense_${CC_ALGO}"

    # Compile BPF if not already done
    if [[ ! -f "${DEFENSE_DIR}/defense_inspector.o" ]]; then
        compile_bpf || {
            log_error "Cannot run defense scenario without BPF object"
            return 1
        }
    fi

    python3 "${SRC_DIR}/topology.py" \
        --cc "$CC_ALGO" --delay "$DELAY_MS" --bw "$BW_MBPS" --queue "$QUEUE_PKTS" \
        --nginx-conf "${CONFIG_DIR}/nginx.conf" &
    local topo_pid=$!
    sleep 5

    python3 -c "
import time, subprocess, os
os.makedirs('${RESULTS_DIR}/${tag}', exist_ok=True)

# Load XDP defense on h1
defense = subprocess.Popen([
    'ip', 'netns', 'exec', 'h1',
    'python3', '${DEFENSE_DIR}/defense_loader.py',
    '--iface', 'h1-eth0',
    '--obj', '${DEFENSE_DIR}/defense_inspector.o',
    '--mode', 'skb',
    '--interval', '0.5',
])

time.sleep(2)

# Telemetry on h1
telem = subprocess.Popen([
    'ip', 'netns', 'exec', 'h1',
    'python3', '${SRC_DIR}/telemetry.py',
    '--interval', '100',
    '--duration', '${DURATION}',
    '--tcp-csv', '${RESULTS_DIR}/${tag}/tcp_metrics.csv',
    '--queue-csv', '${RESULTS_DIR}/${tag}/queue_metrics.csv',
    '--router-iface', 'r1-eth1',
    '--ns-cmd', 'ip netns exec r1',
])

time.sleep(2)

# Honest client on h3
honest = subprocess.Popen([
    'ip', 'netns', 'exec', 'h3',
    'python3', '${SRC_DIR}/honest_client.py',
    '--url', 'http://10.0.1.2/video.mp4',
    '--output', '${RESULTS_DIR}/${tag}/honest_throughput.csv',
    '--duration', '${DURATION}',
])

time.sleep(5)

# Optimistic ACK attacker on h2
attacker = subprocess.Popen([
    'ip', 'netns', 'exec', 'h2',
    'python3', '${SRC_DIR}/optimistic_client.py',
    '--server', '10.0.1.2',
    '--port', '80',
    '--delta', '${OPT_DELTA}',
    '--rate', '${OPT_RATE}',
    '--duration', str(${DURATION} - 10),
])

time.sleep(${DURATION} + 5)

for p in [defense, telem, honest, attacker]:
    try:
        p.terminate()
        p.wait(timeout=5)
    except:
        p.kill()
" 2>&1 | tee "${LOGS_DIR}/${tag}.log" || true

    kill $topo_pid 2>/dev/null || true
    wait $topo_pid 2>/dev/null || true
    mn -c 2>/dev/null || true

    log_info "Defense results saved to ${RESULTS_DIR}/${tag}/"
}

# ──────────────────────────────────────────────────────────────────
# Results summary
# ──────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    log_step "═══ EXPERIMENT RESULTS SUMMARY ═══"
    echo ""

    for scenario_dir in "${RESULTS_DIR}"/*/; do
        scenario=$(basename "$scenario_dir")
        echo -e "${BLUE}--- ${scenario} ---${NC}"

        if [[ -f "${scenario_dir}/honest_throughput.csv" ]]; then
            # Calculate average throughput from CSV
            avg=$(python3 -c "
import csv
vals = []
with open('${scenario_dir}/honest_throughput.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        try:
            vals.append(float(row['goodput_mbps']))
        except (KeyError, ValueError):
            pass
if vals:
    print(f'Avg goodput: {sum(vals)/len(vals):.2f} Mbps  '
          f'Min: {min(vals):.2f} Mbps  '
          f'Max: {max(vals):.2f} Mbps  '
          f'Samples: {len(vals)}')
else:
    print('No throughput data')
" 2>/dev/null || echo "  (analysis failed)")
            echo "  $avg"
        fi

        if [[ -f "${scenario_dir}/tcp_metrics.csv" ]]; then
            cwnd_info=$(python3 -c "
import csv
vals = []
with open('${scenario_dir}/tcp_metrics.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        try:
            v = int(row['cwnd'])
            vals.append(v)
        except (KeyError, ValueError):
            pass
if vals:
    print(f'cwnd — Avg: {sum(vals)/len(vals):.0f}  '
          f'Max: {max(vals)}  Samples: {len(vals)}')
else:
    print('No cwnd data')
" 2>/dev/null || echo "  (analysis failed)")
            echo "  $cwnd_info"
        fi
        echo ""
    done

    log_info "Full CSV data in: ${RESULTS_DIR}/"
    log_info "Experiment logs in: ${LOGS_DIR}/"
}

# ──────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────
main() {
    local scenario="${1:-all}"

    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  CSE 406: TCP Optimistic ACK Analysis Lab               ║${NC}"
    echo -e "${BLUE}║  Dumbbell Topology — Mininet Testbed                    ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    preflight
    ensure_video

    case "$scenario" in
        baseline)
            run_baseline
            ;;
        attack)
            run_attack
            ;;
        defense)
            run_defense
            ;;
        all)
            run_baseline
            sleep 3
            run_attack
            sleep 3
            run_defense
            ;;
        *)
            echo "Usage: $0 [baseline|attack|defense|all]"
            exit 1
            ;;
    esac

    print_summary
}

main "$@"
