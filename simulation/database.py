"""SQLite storage for CTI fingerprint records."""
from __future__ import annotations

import sqlite3

import pandas as pd

SCHEMA = """
CREATE TABLE IF NOT EXISTS cti_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen TEXT,
    fingerprint TEXT UNIQUE,
    threat_type TEXT,
    source_id TEXT,
    target_satellite TEXT,
    confidence REAL,
    ioc_summary TEXT,
    reason TEXT
)
"""


def init_db(path: str = "data/cti_fingerprints.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def store_records(conn: sqlite3.Connection, records: pd.DataFrame) -> int:
    if records.empty:
        return 0
    rows = [
        (str(r.timestamp), r.fingerprint, r.threat_type, r.source_id,
         r.target_satellite, r.confidence, r.ioc_summary, r.reason)
        for r in records.itertuples()
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO cti_fingerprints "
        "(first_seen, fingerprint, threat_type, source_id, target_satellite, "
        "confidence, ioc_summary, reason) VALUES (?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    return len(rows)


def load_records(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT first_seen, fingerprint, threat_type, source_id, "
        "target_satellite, confidence, ioc_summary, reason "
        "FROM cti_fingerprints ORDER BY confidence DESC",
        conn,
    )
