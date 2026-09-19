#!/usr/bin/env python3

import argparse
import csv
import logging
import os
import signal
import sys
import time
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Honest] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("honest_client")

CHUNK_SIZE = 65536

def download_with_telemetry(url, output_csv, duration):
    log.info("Starting download: %s", url)
    log.info("Throughput log: %s", output_csv)

    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)

    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["timestamp", "elapsed_s", "bytes_this_interval",
                          "goodput_mbps", "total_bytes"])

        try:
            resp = urllib.request.urlopen(url, timeout=10)
        except Exception as e:
            log.error("Connection failed: %s", e)
            sys.exit(1)

        total_bytes = 0
        interval_bytes = 0
        start_time = time.monotonic()
        interval_start = start_time
        sample_id = 0

        try:
            while True:
                chunk = resp.read(CHUNK_SIZE)
                if not chunk:
                    break

                total_bytes += len(chunk)
                interval_bytes += len(chunk)

                now = time.monotonic()
                elapsed_total = now - start_time

                if duration > 0 and elapsed_total >= duration:
                    break

                interval_elapsed = now - interval_start
                if interval_elapsed >= 1.0:
                    goodput_mbps = (interval_bytes * 8) / (interval_elapsed * 1e6)
                    writer.writerow([
                        f"{now:.3f}",
                        f"{elapsed_total:.1f}",
                        interval_bytes,
                        f"{goodput_mbps:.4f}",
                        total_bytes,
                    ])
                    csvfile.flush()

                    sample_id += 1
                    if sample_id % 5 == 0:
                        log.info("t=%.0fs  goodput=%.2f Mbps  total=%.1f MB",
                                 elapsed_total, goodput_mbps, total_bytes / 1e6)

                    interval_bytes = 0
                    interval_start = now

        except KeyboardInterrupt:
            log.info("Download interrupted by user")

        finally:
            resp.close()
            total_elapsed = time.monotonic() - start_time
            avg_mbps = (total_bytes * 8) / (total_elapsed * 1e6) if total_elapsed > 0 else 0
            log.info("=== Download Summary ===")
            log.info("Total bytes:    %d (%.2f MB)", total_bytes, total_bytes / 1e6)
            log.info("Duration:       %.1f s", total_elapsed)
            log.info("Avg goodput:    %.2f Mbps", avg_mbps)

def main():
    parser = argparse.ArgumentParser(
        description="Honest HTTP download client with throughput logging"
    )
    parser.add_argument("--url", default="http://10.0.0.1/video.mp4",
                        help="URL to download (default: http://10.0.0.1/video.mp4)")
    parser.add_argument("--output", default="/tmp/cse406/results/honest_throughput.csv",
                        help="CSV output path for throughput samples")
    parser.add_argument("--duration", type=int, default=0,
                        help="Max download duration in seconds (0 = until complete)")
    args = parser.parse_args()

    download_with_telemetry(args.url, args.output, args.duration)

if __name__ == "__main__":
    main()
