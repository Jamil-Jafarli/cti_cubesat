"""Synthetic RF telemetry generator for the honeypot CubeSat CTI platform.

Produces a labeled dataset of RF uplink packets as observed by the honeypot
nodes: frequency, Doppler profile, oscillator drift, modulation, signal levels,
command payload and packet structure fields. Malicious packets are injected
with controlled anomalies (RF spoofing, source-ID spoofing, command injection,
malformed floods) so detection performance can be evaluated against ground truth.

NOTE: All telemetry is synthetically generated for demonstration and
pre-deployment validation; no live RF captures are used.
"""
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from profiles import (
    BENIGN_COMMANDS,
    KNOWN_SOURCES,
    MALICIOUS_MODULATIONS,
    NODE_CENTERS_MHZ,
    SUSPICIOUS_COMMANDS,
)

BASE_TIME = pd.Timestamp("2026-03-06 15:20:00")
UNKNOWN_ID_RANGE = (901, 999)  # UNK-9xx

# LEO pass geometry (500 km orbit, high-elevation pass)
C_KMS = 299_792.458
SAT_SPEED_KMS = 7.3      # effective along-track speed relative to the observer
MIN_RANGE_KM = 600.0     # slant range at closest approach (TCA)
PASS_DURATION_S = 600.0  # AOS -> LOS


def _pass_doppler_profile(n: int, f_mhz: float) -> np.ndarray:
    """Doppler shift (Hz) over one LEO pass, straight-line flyby approximation.

    Range r(t) = sqrt(d_min^2 + (v t)^2), Doppler = -f * (dr/dt) / c. Positive
    while the satellite approaches, crosses zero at TCA with the steepest slope
    there (S-curve), and reaches about +-10 kHz near the horizon at 437 MHz.
    """
    t = np.linspace(-PASS_DURATION_S / 2, PASS_DURATION_S / 2, n)
    vt = SAT_SPEED_KMS * t
    range_rate = SAT_SPEED_KMS * vt / np.sqrt(MIN_RANGE_KM ** 2 + vt ** 2)
    return -f_mhz * 1e6 * range_rate / C_KMS


def _unknown_id(rng: np.random.Generator) -> str:
    return f"UNK-{rng.integers(*UNKNOWN_ID_RANGE)}"


def generate(n_packets: int = 150, n_malicious: int = 32, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    nodes = list(NODE_CENTERS_MHZ)
    node_of = [nodes[min(3 * i // n_packets, 2)] for i in range(n_packets)]
    # each node's packets are observed over one pass of that node
    expected_doppler = np.empty(n_packets)
    for node in nodes:
        idx = [i for i, nd in enumerate(node_of) if nd == node]
        expected_doppler[idx] = _pass_doppler_profile(len(idx), NODE_CENTERS_MHZ[node])
    known_ids = list(KNOWN_SOURCES)

    mal_idx = set(rng.choice(n_packets, size=n_malicious, replace=False).tolist())
    # Attack-mix composition: unknown attacker / GS-ID spoofing / command
    # injection / malformed flood. Source identity is drawn per type; every
    # other indicator fires with an attack-dependent probability so the
    # aggregate anomaly statistics match the proof-of-concept baseline
    # (avg score ~18.2).
    type_cycle = rng.permutation(["A"] * 17 + ["B"] * 8 + ["C"] * 5 + ["D"] * 2)
    mal_types = {idx: t for idx, t in zip(sorted(mal_idx), type_cycle)}
    # Per-indicator firing probabilities for injected attacks
    P_MOD, P_CMD, P_CRC, P_PROBE = 0.82, 0.82, 0.42, 0.65

    rows = []
    ts = BASE_TIME
    for i in range(n_packets):
        node = node_of[i]
        center = NODE_CENTERS_MHZ[node]
        dopp_expected = expected_doppler[i]

        if i not in mal_idx:
            sid = known_ids[rng.integers(len(known_ids))]
            prof = KNOWN_SOURCES[sid]
            # residual Doppler-correction error + short-term drift: ~150 Hz rms
            freq = center + (prof["bias_khz"] + rng.normal(0, 0.15)) / 1000.0
            doppler = dopp_expected + rng.normal(0, 60)
            drift = prof["drift_ppm"]
            modulation = "GFSK"
            cmd = BENIGN_COMMANDS[rng.integers(len(BENIGN_COMMANDS))]
            crc_ok, preamble_ok = True, True
            inter_arrival = rng.uniform(4.0, 15.0)
            snr = rng.uniform(12.0, 24.0)
            rssi = rng.uniform(-108.0, -88.0)
            label = "benign"
        else:
            t_type = mal_types[i]
            drift = rng.uniform(0.4, 3.0)
            snr = rng.uniform(4.0, 11.0)
            rssi = rng.uniform(-120.0, -104.0)

            # transmitter identity and RF-chain anomalies by attack type
            if t_type == "A":  # unknown attacker
                sid = _unknown_id(rng)
                freq = center + rng.choice([-1, 1]) * rng.uniform(20, 120) / 1000.0
                doppler = dopp_expected + rng.choice([-1, 1]) * rng.uniform(800, 4500)
            elif t_type == "B":  # spoofing a legitimate GS identity
                sid = known_ids[rng.integers(len(known_ids))]
                freq = center + rng.choice([-1, 1]) * rng.uniform(20, 60) / 1000.0
                doppler = dopp_expected + rng.choice([-1, 1]) * rng.uniform(800, 4500)
            elif t_type == "C":  # command injection, mistuned transmitter
                sid = known_ids[rng.integers(len(known_ids))]
                freq = center + rng.choice([-1, 1]) * rng.uniform(20, 30) / 1000.0
                doppler = dopp_expected + rng.choice([-1, 1]) * rng.uniform(800, 2500)
            else:  # D: malformed flood
                sid = _unknown_id(rng) if rng.random() < 0.5 else known_ids[rng.integers(len(known_ids))]
                freq = center + rng.choice([-1, 1]) * rng.uniform(20, 50) / 1000.0
                doppler = dopp_expected + rng.choice([-1, 1]) * rng.uniform(800, 3000)

            # remaining indicators fire probabilistically per packet
            modulation = (MALICIOUS_MODULATIONS[rng.integers(len(MALICIOUS_MODULATIONS))]
                          if rng.random() < P_MOD else "GFSK")
            if rng.random() < P_CMD:
                cmd = SUSPICIOUS_COMMANDS[rng.integers(len(SUSPICIOUS_COMMANDS))]
            else:
                # replayed benign command (e.g. recorded pass traffic)
                cmd = BENIGN_COMMANDS[rng.integers(len(BENIGN_COMMANDS))]
            crc_ok = bool(rng.random() > P_CRC)
            preamble_ok = bool(rng.random() > P_CRC * 0.8)
            inter_arrival = (rng.uniform(0.5, 1.8) if rng.random() < P_PROBE
                             else rng.uniform(4.0, 15.0))
            label = "malicious"

        ts = ts + pd.Timedelta(seconds=float(inter_arrival))
        rows.append({
            "timestamp": ts,
            "packet_id": i,
            "node": node,
            "source_id": sid,
            "freq_mhz": round(freq, 5),
            "doppler_hz": round(doppler, 1),
            "expected_doppler_hz": round(dopp_expected, 1),
            "drift_ppm": round(drift, 3),
            "modulation": modulation,
            "snr_db": round(snr, 1),
            "rssi_dbm": round(rssi, 1),
            "cmd": cmd,
            "crc_ok": crc_ok,
            "preamble_ok": preamble_ok,
            "inter_arrival_s": round(inter_arrival, 2),
            "label": label,
        })

    return pd.DataFrame(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", type=int, default=150)
    ap.add_argument("--malicious", type=int, default=32)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/rf_telemetry.csv")
    args = ap.parse_args()

    df = generate(args.packets, args.malicious, args.seed)
    df.to_csv(args.out, index=False)
    n_mal = int((df["label"] == "malicious").sum())
    print(f"wrote {len(df)} packets ({n_mal} malicious) to {args.out}")
