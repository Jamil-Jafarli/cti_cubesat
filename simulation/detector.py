"""Detection engine: anomaly scoring, fuzzy transmitter matching, CTI fingerprints.

Implements the detection logic described in docs/detection.md:

1. Indicator-based anomaly score (0-100) from seven weighted indicators:
   frequency deviation, Doppler mismatch, unexpected modulation, suspicious
   command, malformed packet, unknown source, aggressive probing.
2. Weighted fuzzy similarity matching of the observed transmission against the
   known ground-station registry (Doppler/drift/modulation feature space).
3. CTI fingerprint record generation (SHA-256 feature-vector hash, IOC summary,
   confidence score) for every packet above the flag threshold.
"""
from __future__ import annotations

import hashlib

import numpy as np
import pandas as pd

from profiles import (
    DOPPLER_RESID_THRESHOLD_HZ,
    EXPECTED_MODULATION,
    FLAG_THRESHOLD,
    FREQ_DEV_THRESHOLD_KHZ,
    FUZZY_KNOWN_MIN,
    FUZZY_SUSPICIOUS_MIN,
    FUZZY_W_DRIFT,
    FUZZY_W_FREQ,
    FUZZY_W_MOD,
    INDICATOR_REASONS,
    INDICATOR_SEVERITY,
    KNOWN_SOURCES,
    NODE_CENTERS_MHZ,
    PROBING_THRESHOLD_S,
    SUSPICIOUS_COMMANDS,
)

CONFIDENCE_CAP = 89.15  # calibrated to proof-of-concept baseline


def detect(df: pd.DataFrame) -> pd.DataFrame:
    """Score each packet and attach detection / fingerprint columns."""
    out = df.copy()
    centers = out["node"].map(NODE_CENTERS_MHZ)
    out["freq_dev_khz"] = (out["freq_mhz"] - centers) * 1000.0
    out["doppler_resid_hz"] = (out["doppler_hz"] - out["expected_doppler_hz"]).abs()

    indicators = {
        "frequency_deviation": out["freq_dev_khz"].abs() > FREQ_DEV_THRESHOLD_KHZ,
        "doppler_mismatch": out["doppler_resid_hz"] > DOPPLER_RESID_THRESHOLD_HZ,
        "unexpected_modulation": out["modulation"] != EXPECTED_MODULATION,
        "suspicious_command": out["cmd"].isin(SUSPICIOUS_COMMANDS),
        "malformed_packet": ~(out["crc_ok"] & out["preamble_ok"]),
        "unknown_source": ~out["source_id"].isin(KNOWN_SOURCES),
        "aggressive_probing": out["inter_arrival_s"] < PROBING_THRESHOLD_S,
    }

    score = np.zeros(len(out))
    for name, mask in indicators.items():
        score += mask.to_numpy() * INDICATOR_SEVERITY[name]
    out["anomaly_score"] = score

    reasons = []
    for i in range(len(out)):
        reasons.append(", ".join(
            INDICATOR_REASONS[name] for name, mask in indicators.items() if mask.iloc[i]
        ))
    out["reason"] = reasons

    fuzzy = out.apply(_fuzzy_similarity, axis=1)
    out["fuzzy_score"] = np.round(fuzzy, 3)
    out["classification"] = np.select(
        [fuzzy >= FUZZY_KNOWN_MIN, fuzzy >= FUZZY_SUSPICIOUS_MIN],
        ["known", "suspicious"],
        default="attacker",
    )

    flagged = out["anomaly_score"] >= FLAG_THRESHOLD
    out["detected"] = flagged
    out["confidence"] = np.where(
        flagged,
        np.round(np.minimum(CONFIDENCE_CAP, 42 + 0.53 * out["anomaly_score"]), 2),
        0.0,
    )

    fp_hashes = [
        hashlib.sha256(
            f"{r.source_id}|{r.freq_mhz:.5f}|{r.doppler_hz:.1f}|{r.drift_ppm}|"
            f"{r.modulation}|{r.cmd}|{r.node}".encode()
        ).hexdigest()[:20].upper()
        for r in out.itertuples()
    ]
    out["fingerprint"] = fp_hashes
    out["ioc_summary"] = [
        f"freq={r.freq_mhz:.5f}MHz, doppler={r.doppler_hz:.1f}Hz, mod={r.modulation}, "
        f"cmd={r.cmd}, snr={r.snr_db}dB, rssi={r.rssi_dbm}dBm"
        for r in out.itertuples()
    ]
    out["threat_type"] = np.where(flagged, "RF Spoofing / Uplink Abuse", "")
    return out


def _fuzzy_similarity(row: pd.Series) -> float:
    """Best weighted similarity of the transmission against the GS registry.

    S = w1*(1 - |df|/df_max) + w2*(1 - |drift diff|/drift_max) + w3*mod_match
    """
    best = 0.0
    for prof in KNOWN_SOURCES.values():
        s_freq = max(0.0, 1.0 - abs(row.freq_dev_khz - prof["bias_khz"]) / 25.0)
        s_drift = max(0.0, 1.0 - abs(row.drift_ppm - prof["drift_ppm"]) / 1.0)
        s_mod = 1.0 if row.modulation == EXPECTED_MODULATION else 0.0
        s = FUZZY_W_FREQ * s_freq + FUZZY_W_DRIFT * s_drift + FUZZY_W_MOD * s_mod
        best = max(best, s)
    return best


def cti_records(scored: pd.DataFrame) -> pd.DataFrame:
    """Fingerprint records for flagged packets, sorted by confidence."""
    cols = ["timestamp", "fingerprint", "threat_type", "source_id", "node",
            "confidence", "ioc_summary", "reason"]
    recs = scored.loc[scored["detected"], cols].rename(columns={"node": "target_satellite"})
    return recs.sort_values("confidence", ascending=False).reset_index(drop=True)


def evaluate(scored: pd.DataFrame) -> dict:
    """Detection performance against ground-truth labels."""
    truth = scored["label"] == "malicious"
    det = scored["detected"]
    tp = int((truth & det).sum())
    fp = int((~truth & det).sum())
    fn = int((truth & ~det).sum())
    tn = int((~truth & ~det).sum())
    return {
        "packets": len(scored),
        "malicious_ground_truth": int(truth.sum()),
        "detections": int(det.sum()),
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "detection_rate": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "avg_anomaly_score": float(scored["anomaly_score"].mean()),
        "max_confidence": float(scored["confidence"].max()),
    }
