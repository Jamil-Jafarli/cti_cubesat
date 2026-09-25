"""Resource profiling: detection latency, memory, and throughput.

Run this ON TARGET HARDWARE (e.g. Raspberry Pi 4 for the ground tier,
or any Linux SBC as an OBC proxy) to obtain the computation-bounds numbers
cited in the paper:
  - mean/median/p99 per-packet detection latency (us)
  - fuzzy-match latency (us)
  - peak memory delta of the pipeline (MB)
  - throughput (packets/s) and per-150-packet batch cost (ms)

For the onboard plugin claim, port the same scoring loop to the ESP32
(FreeRTOS task) and measure loop time + heap there; this script's SBC
numbers complement, not replace, that measurement.
"""
from __future__ import annotations

import json
import platform
import resource
import time

import numpy as np

from detector import _fuzzy_similarity, detect
from generator import generate


def profile(n_packets: int = 150, n_malicious: int = 32, seed: int = 42,
            runs: int = 50) -> dict:
    df = generate(n_packets, n_malicious, seed)

    # per-packet end-to-end detection latency over repeated runs
    lat = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        detect(df)
        lat.append((time.perf_counter_ns() - t0) / len(df) / 1000.0)  # us/packet
    lat = np.array(lat)

    # isolated fuzzy-match latency
    scored = detect(df)
    ft = []
    for _, row in scored.iterrows():
        t0 = time.perf_counter_ns()
        _fuzzy_similarity(row)
        ft.append((time.perf_counter_ns() - t0) / 1000.0)
    ft = np.array(ft)

    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

    return {
        "host": platform.machine(),
        "cpu": platform.processor() or platform.machine(),
        "packets_per_batch": n_packets,
        "detection_latency_us": {
            "mean": float(lat.mean()),
            "p50": float(np.percentile(lat, 50)),
            "p99": float(np.percentile(lat, 99)),
        },
        "fuzzy_match_latency_us": {
            "mean": float(ft.mean()),
            "p99": float(np.percentile(ft, 99)),
        },
        "batch_wall_time_ms": float(lat.mean() * n_packets / 1000.0),
        "throughput_packets_per_s": float(1e6 / lat.mean()),
        "peak_rss_mb": rss_mb,
    }


if __name__ == "__main__":
    result = profile()
    print(json.dumps(result, indent=2))
    with open("out/resource_profile.json", "w") as f:
        json.dump(result, f, indent=2)
