"""Offline pipeline: generate -> detect -> store -> figures + evaluation.

Run after any parameter change; produces the evaluation artifacts:
  out/fig_frequency.png   Observed RF frequency by packet (per honeypot node)
  out/fig_anomaly.png     Anomaly score trend
  out/fig_sources.png     Top malicious source identifiers
  out/cti_fingerprints.csv
  data/cti_fingerprints.db
"""
from __future__ import annotations

import argparse
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from database import init_db, store_records
from detector import cti_records, detect, evaluate
from generator import generate

NODE_COLORS = {"HNY-1": "#4C9BD6", "HNY-2": "#F59E42", "HNY-3": "#52B368"}


def save_figures(scored, out_dir="out", dpi=300):
    os.makedirs(out_dir, exist_ok=True)

    fig, ax = plt.subplots(figsize=(8, 4.2))
    for node, grp in scored.groupby("node"):
        ax.scatter(grp["packet_id"], grp["freq_mhz"], s=42, color=NODE_COLORS[node],
                   label=node, alpha=0.85, edgecolors="none")
    ax.set_title("Observed RF Frequency by Packet")
    ax.set_xlabel("Packet Index")
    ax.set_ylabel("Frequency (MHz)")
    ax.legend(title=None)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "fig_frequency.png"), dpi=dpi)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.plot(scored["packet_id"], scored["anomaly_score"])
    ax.set_title("Anomaly Score Trend")
    ax.set_xlabel("Packet Index")
    ax.set_ylabel("Anomaly Score")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "fig_anomaly.png"), dpi=dpi)
    plt.close(fig)

    mal = scored[scored["detected"]]
    top = mal["source_id"].value_counts().head(10)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.bar(top.index, top.values, color="#1f77b4")
    ax.set_title("Top Malicious Sources")
    ax.set_xlabel("Source ID")
    ax.set_ylabel("Detections")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "fig_sources.png"), dpi=dpi)
    plt.close(fig)


def run(n_packets=150, n_malicious=32, seed=42, out_dir="out"):
    os.makedirs("data", exist_ok=True)
    os.makedirs(out_dir, exist_ok=True)
    df = generate(n_packets, n_malicious, seed)
    scored = detect(df)
    records = cti_records(scored)

    df.to_csv("data/rf_telemetry.csv", index=False)
    records.to_csv(os.path.join(out_dir, "cti_fingerprints.csv"), index=False)
    conn = init_db()
    store_records(conn, records)
    conn.close()

    save_figures(scored, out_dir)
    metrics = evaluate(scored)
    return scored, records, metrics


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", type=int, default=150)
    ap.add_argument("--malicious", type=int, default=32)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="out")
    args = ap.parse_args()

    _, records, metrics = run(args.packets, args.malicious, args.seed, args.out)
    print(f"packets                : {metrics['packets']}")
    print(f"malicious (ground truth): {metrics['malicious_ground_truth']}")
    print(f"detections             : {metrics['detections']}  "
          f"(TP={metrics['TP']} FP={metrics['FP']} FN={metrics['FN']} TN={metrics['TN']})")
    print(f"detection rate         : {metrics['detection_rate']:.3f}")
    print(f"false positive rate    : {metrics['false_positive_rate']:.3f}")
    print(f"avg anomaly score      : {metrics['avg_anomaly_score']:.2f}")
    print(f"max CTI confidence     : {metrics['max_confidence']:.2f}")
    print(f"CTI fingerprint records: {len(records)}")
