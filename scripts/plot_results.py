#!/usr/bin/env python3

import argparse
import csv
import os
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
except ImportError:
    print("matplotlib required: pip install matplotlib")
    sys.exit(1)

def load_csv(path, fields):
    data = {f: [] for f in fields}
    if not os.path.exists(path):
        return data
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            for field in fields:
                try:
                    data[field].append(float(row.get(field, 0) or 0))
                except (ValueError, TypeError):
                    data[field].append(0.0)
    return data

def plot_throughput(results_dir, output_dir):
    fig, ax = plt.subplots(figsize=(10, 5))

    scenarios = {
        "baseline_cubic": ("Baseline", "#2196F3", "-"),
        "attack_cubic":   ("Under Attack", "#F44336", "--"),
        "defense_cubic":  ("With Defense", "#4CAF50", "-."),
    }

    for folder, (label, color, ls) in scenarios.items():
        path = os.path.join(results_dir, folder, "honest_throughput.csv")
        data = load_csv(path, ["elapsed_s", "goodput_mbps"])
        if data["elapsed_s"]:
            ax.plot(data["elapsed_s"], data["goodput_mbps"],
                    label=label, color=color, linestyle=ls, linewidth=1.5)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Goodput (Mbps)")
    ax.set_title("Honest Client Goodput — Baseline vs Attack vs Defense")
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "throughput_comparison.png"), dpi=150)
    plt.close(fig)
    print(f"  → {output_dir}/throughput_comparison.png")

def load_flow_cwnd(path, role):
    xs, ys = [], []
    if not os.path.exists(path):
        return xs, ys
    with open(path) as f:
        for row in csv.DictReader(f):
            if row.get("role") != role:
                continue
            try:
                xs.append(float(row.get("elapsed_s", 0) or 0))
                ys.append(float(row.get("cwnd", 0) or 0))
            except (ValueError, TypeError):
                pass
    return xs, ys

def plot_cwnd(results_dir, output_dir):
    fig, ax = plt.subplots(figsize=(10, 5))

    scenarios = {
        "baseline_cubic": ("Baseline", "#2196F3"),
        "attack_cubic":   ("Attack", "#F44336"),
        "defense_cubic":  ("Defense", "#4CAF50"),
    }
    roles = {"honest": ("-", "honest"), "attacker": ("--", "attacker")}

    plotted = False
    for folder, (label, color) in scenarios.items():
        path = os.path.join(results_dir, folder, "tcp_metrics.csv")
        for role, (ls, suffix) in roles.items():
            xs, ys = load_flow_cwnd(path, role)
            if xs:
                ax.plot(xs, ys, label=f"{label} — {suffix}",
                        color=color, linestyle=ls, linewidth=1.5)
                plotted = True

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("cwnd (segments)")
    ax.set_title("Server Congestion Window per Flow — Baseline vs Attack vs Defense")
    if plotted:
        ax.legend(fontsize=8)
    else:
        ax.text(0.5, 0.5, "No per-flow cwnd data\n(re-run experiments to "
                "regenerate tcp_metrics.csv with the 'role' column)",
                ha="center", va="center", transform=ax.transAxes, fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "cwnd_comparison.png"), dpi=150)
    plt.close(fig)
    print(f"  → {output_dir}/cwnd_comparison.png")

def plot_queue(results_dir, output_dir):
    fig, ax = plt.subplots(figsize=(10, 5))

    scenarios = {
        "baseline_cubic": ("Baseline", "#2196F3", "-"),
        "attack_cubic":   ("Under Attack", "#F44336", "--"),
        "defense_cubic":  ("With Defense", "#4CAF50", "-."),
    }

    for folder, (label, color, ls) in scenarios.items():
        path = os.path.join(results_dir, folder, "queue_metrics.csv")
        data = load_csv(path, ["elapsed_s", "backlog_pkts", "dropped"])
        if data["elapsed_s"]:
            ax.plot(data["elapsed_s"], data["backlog_pkts"],
                    label=f"{label} (backlog)", color=color,
                    linestyle=ls, linewidth=1.5)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Queue Backlog (packets)")
    ax.set_title("Bottleneck Queue Occupancy — Baseline vs Attack vs Defense")
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "queue_comparison.png"), dpi=150)
    plt.close(fig)
    print(f"  → {output_dir}/queue_comparison.png")

def plot_summary_bars(results_dir, output_dir):
    scenarios = ["baseline_cubic", "attack_cubic", "defense_cubic"]
    labels = ["Baseline", "Attack", "Defense"]
    colors = ["#2196F3", "#F44336", "#4CAF50"]
    avgs = []

    for folder in scenarios:
        path = os.path.join(results_dir, folder, "honest_throughput.csv")
        data = load_csv(path, ["goodput_mbps"])
        vals = [v for v in data["goodput_mbps"] if v > 0]
        avgs.append(sum(vals) / len(vals) if vals else 0)

    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(labels, avgs, color=colors, edgecolor="white", linewidth=1.5)

    for bar, val in zip(bars, avgs):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                f"{val:.2f}", ha="center", va="bottom", fontweight="bold")

    ax.set_ylabel("Average Goodput (Mbps)")
    ax.set_title("Honest Client Average Throughput — Scenario Comparison")
    ax.set_ylim(0, max(avgs) * 1.3 if avgs else 10)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "summary_comparison.png"), dpi=150)
    plt.close(fig)
    print(f"  → {output_dir}/summary_comparison.png")

def main():
    parser = argparse.ArgumentParser(description="Plot experiment results")
    parser.add_argument("--results", default="/tmp/cse406/results",
                        help="Results directory")
    parser.add_argument("--output", default="/tmp/cse406/results/plots",
                        help="Output directory for plots")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    print("Generating plots...")

    plot_throughput(args.results, args.output)
    plot_cwnd(args.results, args.output)
    plot_queue(args.results, args.output)
    plot_summary_bars(args.results, args.output)

    print(f"\nAll plots saved to: {args.output}/")

if __name__ == "__main__":
    main()
