"""Streamlit dashboard: Honeypot CubeSat RF Threat Intelligence.

Run:  streamlit run dashboard.py

Mirrors the proof-of-concept dashboard: KPI cards, detection logic panel,
live packet feed, analytics plots, and the CTI fingerprint table with CSV export.
All telemetry is synthetic (see generator.py).
"""
from __future__ import annotations

import pandas as pd
import streamlit as st

from detector import cti_records, detect, evaluate
from export import NODE_COLORS
from generator import generate
from profiles import INDICATOR_REASONS, INDICATOR_SEVERITY

st.set_page_config(page_title="Honeypot CubeSat RF Threat Intelligence", layout="wide")

st.title("Honeypot CubeSat RF Threat Intelligence Dashboard")
st.caption(
    "Synthetic RF telemetry generation, anomaly detection, source spoofing analysis "
    "and CTI fingerprint table — for demonstration purposes."
)

with st.sidebar:
    st.header("Simulation Controls")
    seed = st.number_input("Random seed", min_value=0, value=42, step=1)
    n_packets = st.slider("Total packets", 50, 500, 150)
    n_malicious = st.slider("Injected malicious packets", 5, 100, 32)
    st.button("Regenerate", type="primary")


@st.cache_data(show_spinner=False)
def pipeline(seed: int, n_packets: int, n_malicious: int):
    df = generate(n_packets, n_malicious, seed)
    scored = detect(df)
    return scored, cti_records(scored), evaluate(scored)


scored, records, metrics = pipeline(seed, n_packets, n_malicious)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Packets", metrics["packets"])
c2.metric("Malicious Detections", metrics["detections"])
c3.metric("Benign Traffic", metrics["TN"] + metrics["FP"])
c4.metric("Avg Anomaly Score", f"{metrics['avg_anomaly_score']:.2f}")

if not records.empty:
    st.info(f"Highest CTI confidence: {records['confidence'].max():.2f} "
            f"| Fingerprints in table: {len(records)}")

with st.expander("Detection Logic", expanded=False):
    for name, severity in INDICATOR_SEVERITY.items():
        st.markdown(f"- **{name.replace('_', ' ').title()}** ({severity}): "
                    f"{INDICATOR_REASONS[name]}.")

tab_feed, tab_analytics, tab_cti = st.tabs(["Live RF Feed", "Analytics", "CTI Fingerprints"])

with tab_feed:
    st.dataframe(
        scored[["timestamp", "packet_id", "node", "source_id", "freq_mhz", "doppler_hz",
                "modulation", "snr_db", "rssi_dbm", "cmd", "anomaly_score",
                "classification", "detected"]],
        use_container_width=True,
        height=420,
    )

with tab_analytics:
    import matplotlib.pyplot as plt
    fig1, ax1 = plt.subplots(figsize=(8, 3.6))
    for node, grp in scored.groupby("node"):
        ax1.scatter(grp["packet_id"], grp["freq_mhz"], s=32, color=NODE_COLORS[node],
                    label=node, alpha=0.85, edgecolors="none")
    ax1.set_title("Observed RF Frequency by Packet")
    ax1.set_xlabel("Packet Index")
    ax1.set_ylabel("Frequency (MHz)")
    ax1.legend()
    fig1.tight_layout()
    st.pyplot(fig1)

    fig2, ax2 = plt.subplots(figsize=(8, 3.2))
    ax2.plot(scored["packet_id"], scored["anomaly_score"])
    ax2.set_title("Anomaly Score Trend")
    ax2.set_xlabel("Packet Index")
    ax2.set_ylabel("Anomaly Score")
    fig2.tight_layout()
    st.pyplot(fig2)

    top = scored[scored["detected"]]["source_id"].value_counts().head(10)
    fig3, ax3 = plt.subplots(figsize=(8, 3.2))
    ax3.bar(top.index, top.values, color="#1f77b4")
    ax3.set_title("Top Malicious Sources")
    ax3.set_xlabel("Source ID")
    ax3.set_ylabel("Detections")
    plt.setp(ax3.get_xticklabels(), rotation=45, ha="right")
    fig3.tight_layout()
    st.pyplot(fig3)

with tab_cti:
    st.subheader("CTI Fingerprint Table")
    st.dataframe(records, use_container_width=True, height=420)
    st.download_button(
        "Export CTI CSV",
        data=records.to_csv(index=False).encode(),
        file_name="cti_fingerprints.csv",
        mime="text/csv",
    )

with st.expander("Evaluation against ground truth"):
    st.json(metrics)
