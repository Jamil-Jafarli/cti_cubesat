#!/usr/bin/env python3
"""CTI server — PHASE 4/5 of the honeypot CubeSat bench.

Takes the CTI records the ground station receives — one `CTI,<csv>` line per
record the honeypot downlinked — stores them in SQLite on disk, and serves the
threat-intel portal (web/) so the ground-station data can be inspected at any
time, including after the RF session has ended.

The ground station is the Raspberry Pi this server runs on, with a Ra-01 on
its SPI bus (gs_cti_pi, started and read by --radio). --serial reads the same
CTI,<csv> lines from any receiver that prints them on a USB serial port.

    python3 hny_server.py --radio --host 0.0.0.0         # Pi + Ra-01
    python3 hny_server.py --serial /dev/ttyACM0          # receiver on USB serial
    python3 hny_server.py --simulate --reset             # no hardware
    # then open http://<host>:8700

CSV field order (HnyProto.h record_to_csv — keep in sync):
    t_ms,src,cmd,freq_dev_khz,dop_hz,rssi,crc_ok,gap_s,score,fuzzy,cls,
    flagged,conf,fp

Source profiles and risk score (paper §4.4, bench form). Records are grouped by
the CLAIMED CALLSIGN, not by the `fp` hash: that hash is the record identifier
and changes with every packet (paper §4.3), so it cannot group traffic. True
transmitter grouping needs the signature pair (residual carrier offset +
short-term oscillator drift); the bench Record carries no drift figure, so it
is out of reach here and is left to the flight build.

    severity = 30 * flagged_ratio          packets above the flag threshold
             + 25 * suspicious_cmd_ratio   share carrying suspicious commands
             + 20 * callsign_unknown       callsign outside the known GS set
             + 15 * min(1, count/20)       persistence
             + 10 * min(1, mean|freq_dev|/20)   RF anomaly vs channel centre
    risk     = min(100, severity * min(1, count/CONFIRM_OBS))

The confirmation factor implements paper §4.4: an entry reaches the blocklist
only once several observations confirm it, so one packet — however suspicious —
cannot by itself produce a high-risk profile. A profile is a blocklist
candidate when it is confirmed (>= CONFIRM_OBS observations) and its risk
reaches BLOCKLIST_RISK_MIN.

Only the Python standard library is required; pyserial is needed solely for
the live --serial mode. --simulate reuses cti_platform's generator + detector
(install platform/requirements.txt first).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import math
import json
import os
import re
import select
import sqlite3
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import cti_engine

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
DB_PATH = os.path.join(HERE, "bench_cti.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,            -- server receipt time (epoch s)
  device_ms INTEGER,           -- honeypot millis() at capture
  src TEXT, cmd TEXT,
  freq_dev_khz REAL, dop_hz REAL, rssi REAL,
  crc_ok INTEGER, gap_s REAL,
  score INTEGER, fuzzy REAL, cls TEXT,
  flagged INTEGER, conf REAL, fp TEXT,
  onboard_score INTEGER,       -- score the honeypot computed (downlink order)
  pass_t_s REAL                -- seconds into the pass, as the analysis placed it
);
"""

# columns added after the first bench runs; existing DBs are migrated in place
MIGRATIONS = [("onboard_score", "INTEGER"), ("pass_t_s", "REAL"),
              ("sig", "TEXT"), ("wl", "INTEGER")]

CSV_FIELDS = ["device_ms", "src", "cmd", "freq_dev_khz", "dop_hz", "rssi",
              "crc_ok", "gap_s", "score", "fuzzy", "cls", "flagged", "conf", "fp"]
# Firmware from 2026-09 appends the transmitter signature and the onboard
# whitelist verdict (0 no entry / 1 match / 2 mismatch). Older boards send the
# 14-field line, so both lengths are accepted and the extras default to None.
CSV_FIELDS_EXT = CSV_FIELDS + ["sig", "wl"]


# ── ground-side Doppler analysis ─────────────────────────────────────────
# The honeypot ships the raw FEI measurement and always sends dop_hz = 0: a
# single fixed receiver cannot separate Doppler from the transmitter's own
# carrier offset, and the onboard score only sets the downlink order anyway
# (paper 4.1, 6.2). Deriving the residual is ground work, and this is it.
#
# Model and constants mirror gs_uplink_pico.ino exactly — keep in sync.
PASS_S = 600.0          # pass length, s
DOP_PEAK_HZ = 6000.0    # bench-scaled peak (see the sketch for why)
SAT_V_MS = 7600.0
SLANT_M = 600000.0

# Bench station carrier biases, kHz (HnyProto.h BENCH_GS). A station not in
# this table has no known bias, so only the Doppler term is removed.
BENCH_BIAS_KHZ = {"GS100": -8.0, "GS102": -4.0, "GS104": 0.0,
                  "GS107": 4.0, "GS109": 8.0}

# Bench callsigns: the five stations above plus the UNKnnn attackers. Rows from
# --simulate carry cti_platform's own scores and GS-nnn callsigns; they are left
# alone so that re-running the analysis cannot overwrite them.
BENCH_SRC = re.compile(r"^(GS10[02479]|UNK\d+)$", re.IGNORECASE)


def _range_rate(t: float) -> float:
    vt = SAT_V_MS * t
    return (SAT_V_MS * SAT_V_MS * t) / math.sqrt(SLANT_M * SLANT_M + vt * vt)


def expected_doppler_hz(t_s: float) -> float:
    """Doppler a legitimate station pre-compensates, t_s seconds into a pass."""
    t = (t_s % PASS_S) - PASS_S / 2.0
    return -DOP_PEAK_HZ * (_range_rate(t) / _range_rate(PASS_S / 2.0))


def doppler_residual_hz(src: str, freq_dev_khz: float, t_s: float) -> float:
    """What is left of the measured carrier offset once the station's known
    bias and the expected pass Doppler are removed. ~0 for a station that
    tracks the satellite; the full profile for one transmitting fixed."""
    bias_hz = BENCH_BIAS_KHZ.get(src.upper(), 0.0) * 1000.0
    return freq_dev_khz * 1000.0 - bias_hz - expected_doppler_hz(t_s)


def db_connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute(SCHEMA)
    con.executescript(cti_engine.SCHEMA)
    have = {r["name"] for r in con.execute("PRAGMA table_info(packets)")}
    for name, decl in MIGRATIONS:
        if name not in have:
            con.execute(f"ALTER TABLE packets ADD COLUMN {name} {decl}")
    con.commit()
    return con


def insert_packet(con, rec: dict, ts: float | None = None) -> None:
    rec = dict(rec)
    rec["ts"] = ts if ts is not None else time.time()
    cols = ["ts"] + CSV_FIELDS_EXT
    con.execute(
        f"INSERT INTO packets ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
        [rec.get(c) for c in cols],
    )
    con.commit()


def parse_cti_line(line: str) -> dict | None:
    """Parse one `CTI,<csv>` serial line into a packet dict, or None."""
    if not line.startswith("CTI,"):
        return None
    parts = next(csv.reader([line[4:]]))
    if len(parts) not in (len(CSV_FIELDS), len(CSV_FIELDS_EXT)):
        return None
    try:
        d = dict(zip(CSV_FIELDS_EXT, parts))
        rec = {
            "device_ms": int(d["device_ms"]), "src": d["src"], "cmd": d["cmd"],
            "freq_dev_khz": float(d["freq_dev_khz"]), "dop_hz": float(d["dop_hz"]),
            "rssi": float(d["rssi"]), "crc_ok": int(d["crc_ok"]),
            "gap_s": float(d["gap_s"]), "score": int(d["score"]),
            "fuzzy": float(d["fuzzy"]), "cls": d["cls"],
            "flagged": int(d["flagged"]), "conf": float(d["conf"]), "fp": d["fp"],
            "sig": d.get("sig") or cti_engine.signature(d["src"],
                                                        float(d["freq_dev_khz"])),
            "wl": int(d["wl"]) if d.get("wl") not in (None, "") else None,
        }
        # The honeypot stopped sending the record hash when records moved to
        # the packed wire format: 20 of the 46 payload bytes a 64-byte FSK
        # FIFO leaves is too much to spend on an identifier the ground can
        # assign itself (HnyProto.h, "downlink wire record"). Same feature
        # string as the firmware, so the two are comparable in shape, not in
        # value — the wire quantises the carrier offset to 10 Hz.
        if not rec["fp"]:
            feat = f"{rec['src']}|{rec['freq_dev_khz']:.5f}|{rec['dop_hz']:.1f}|{rec['cmd']}"
            rec["fp"] = hashlib.sha256(feat.encode()).hexdigest()[:20].upper()
        return rec
    except ValueError:
        return None


# ── ground analysis ──────────────────────────────────────────────────────
# This is the "final analysis is done on the ground" step of paper 6.2. The
# honeypot's own score is kept in onboard_score (it only sets downlink order);
# score/flagged/conf below are the authoritative figures.

def _ground_score(row: sqlite3.Row, resid_hz: float) -> tuple[int, int, float]:
    """7-indicator score, same weights as HnyProto.h / detector.py.
    The modulation indicator cannot fire on the bench (GFSK only, paper 6.4)."""
    s = 0
    if abs(row["freq_dev_khz"]) > 20.0:               s += 25   # frequency
    if abs(resid_hz) > 700.0:                         s += 25   # Doppler
    if (row["cmd"] or "").upper() in SUSP_CMDS_UC:    s += 15   # command
    if not row["crc_ok"]:                             s += 10   # malformed
    if not KNOWN_CALLSIGN.match(row["src"] or ""):    s += 5    # unknown source
    if row["gap_s"] is not None and row["gap_s"] < 2.0: s += 5  # probing
    conf = min(42.0 + 0.53 * s, 89.15)
    return s, int(s >= FLAG_MIN), conf


def estimate_pass_offset(rows: list) -> float:
    """Where the honeypot's millis() clock sits inside the transmitter's pass.

    The two boards boot independently, so their clocks differ by an unknown
    constant. Legitimate stations pre-compensate Doppler, so their residual is
    zero at the true offset: scan one-second steps and take the offset with the
    smallest median |residual| over known callsigns. The median keeps spoofed
    frames sent from a known callsign from dragging the estimate."""
    ref = [r for r in rows if r["src"] and r["src"].upper() in BENCH_BIAS_KHZ]
    if not ref:
        return 0.0
    base = min(r["device_ms"] for r in rows)
    best, best_err = 0.0, float("inf")
    for off in range(0, int(PASS_S)):
        errs = sorted(abs(doppler_residual_hz(
            r["src"], r["freq_dev_khz"],
            (r["device_ms"] - base) / 1000.0 + off)) for r in ref)
        med = errs[len(errs) // 2]
        if med < best_err:
            best, best_err = float(off), med
    return best


def analyse_ground(con) -> int:
    """Derive the Doppler residual and the authoritative score for every row."""
    allrows = con.execute("SELECT * FROM packets ORDER BY device_ms").fetchall()
    rows = [r for r in allrows if BENCH_SRC.match(r["src"] or "")]
    skipped = len(allrows) - len(rows)
    if not rows:
        print(f"[server] ground analysis: no bench records ({skipped} skipped)")
        return 0
    base = min(r["device_ms"] for r in rows)
    off = estimate_pass_offset(rows)
    for r in rows:
        t_s = (r["device_ms"] - base) / 1000.0 + off
        resid = doppler_residual_hz(r["src"] or "", r["freq_dev_khz"], t_s)
        score, flagged, conf = _ground_score(r, resid)
        con.execute(
            "UPDATE packets SET dop_hz=?, score=?, flagged=?, conf=?, "
            "onboard_score=COALESCE(onboard_score, score), pass_t_s=? WHERE id=?",
            (round(resid, 1), score, flagged, round(conf, 2), round(t_s % PASS_S, 1),
             r["id"]),
        )
    con.commit()
    fired = cti_engine.evaluate(con)
    print(f"[server] ground analysis: {len(rows)} records, pass offset {off:.0f} s"
          + (f", {skipped} non-bench rows left alone" if skipped else "")
          + (f", {fired} new alert(s)" if fired else ""))
    return len(rows)


# ── ingestion ────────────────────────────────────────────────────────────

GS_PI_BIN = os.path.join(HERE, "..", "gs_cti_pi", "build", "gs_cti_pi")


def _ingest_line(con, line: str, tag: str) -> bool:
    """Store one ground-station line if it is a CTI record, else echo it.
    Returns True when a record was stored."""
    rec = parse_cti_line(line)
    if rec:
        insert_packet(con, rec)
        print(f"[server] stored: {rec['src']} {rec['cmd']} "
              f"onboard_score={rec['score']} {rec['cls']}")
        return True
    if line:
        print(line if line.startswith("[") else f"[{tag}] {line}")
    return False


def ingest_serial(con, port: str, baud: int) -> None:
    import serial  # pyserial, only needed here

    while True:
        try:
            with serial.Serial(port, baud, timeout=2) as ser:
                print(f"[server] reading {port} @ {baud}")
                buf = b""
                pending = False          # records stored since the last analysis
                while True:
                    chunk = ser.read(256)
                    buf += chunk
                    # a downlink arrives as a burst; when the line goes quiet
                    # the batch is complete and the ground analysis can run
                    if not chunk and pending:
                        analyse_ground(con)
                        pending = False
                    while b"\n" in buf:
                        raw, buf = buf.split(b"\n", 1)
                        line = raw.decode("utf-8", "replace").strip()
                        pending |= _ingest_line(con, line, "pico")
        except Exception as e:  # unplugged / reflashed — wait and retry
            print(f"[server] serial: {e}; retrying in 3 s")
            time.sleep(3)


def ingest_radio(con, binary: str, rssi_threshold: float | None) -> None:
    """Run the Pi ground-station receiver (gs_cti_pi) and read its stdout.
    Same batching as the serial path: once the downlink goes quiet for 2 s,
    the ground analysis runs over what arrived. The receiver is restarted if
    it ever exits. Lines are decoded with errors="replace": the honeypot keeps
    malformed uplink frames as evidence, so a downlinked command field can
    carry arbitrary bytes, and one such record once stopped this thread."""
    cmd = [binary]
    if rssi_threshold is not None:
        cmd += ["--rssi-threshold", str(rssi_threshold)]
    while True:
        try:
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, errors="replace", bufsize=1) as proc:
                print(f"[server] radio receiver started: {' '.join(cmd)}")
                pending = False
                while True:
                    ready, _, _ = select.select([proc.stdout], [], [], 2.0)
                    if not ready:
                        if pending:
                            analyse_ground(con)
                            pending = False
                        continue
                    line = proc.stdout.readline()
                    if not line:                         # receiver exited
                        break
                    pending |= _ingest_line(con, line.strip(), "gs")
                if pending:
                    analyse_ground(con)
                print(f"[server] radio receiver exited with code {proc.wait()}; "
                      f"restarting in 3 s")
        except OSError as e:
            print(f"[server] radio receiver: {e}; build it with gs_cti_pi/build.sh; "
                  f"retrying in 3 s")
        except Exception as e:  # never let one bad line end ingestion
            print(f"[server] radio ingestion error: {e!r}; restarting receiver in 3 s")
        time.sleep(3)


def ingest_simulate(con, n_packets: int) -> None:
    sys.path.insert(0, os.path.join(HERE, "..", "..", "platform"))
    from generator import generate
    from detector import detect

    scored = detect(generate(n_packets=n_packets))
    t_min = scored["timestamp"].min().timestamp()
    t0 = time.time()
    for r in scored.itertuples():
        rel = r.timestamp.timestamp() - t_min
        insert_packet(con, {
            "device_ms": int(rel * 1000),
            "src": r.source_id, "cmd": r.cmd,
            "freq_dev_khz": round(float(r.freq_dev_khz), 2),
            "dop_hz": round(float(r.doppler_resid_hz), 0),
            "rssi": round(float(r.rssi_dbm), 1),
            "crc_ok": int(bool(r.crc_ok)),
            "gap_s": round(float(r.inter_arrival_s), 2),
            "score": int(r.anomaly_score), "fuzzy": float(r.fuzzy_score),
            "cls": r.classification, "flagged": int(bool(r.detected)),
            "conf": float(r.confidence), "fp": r.fingerprint,
        }, ts=t0 + rel)
    print(f"[server] simulated {len(scored)} packets from cti_platform")


# ── portal state ─────────────────────────────────────────────────────────

SUSP_CMDS = ("REBOOT", "OVERRIDE", "0x7F_UNKNOWN_OPCODE",
             "ERASE_FLASH", "SET_MODE=DEBUG", "DISABLE_COMMS")
# Upper-cased for case-insensitive lookup. Matching on cmd.upper() against the
# tuple above silently misses "0x7F_UNKNOWN_OPCODE", whose own spelling is
# mixed case; HnyProto.h compares it exactly, so the two must not drift.
SUSP_CMDS_UC = frozenset(c.upper() for c in SUSP_CMDS)
FLAG_MIN = 50
# cooperative ground stations: GS-100…GS-115 (platform) and GS100…GS109 (bench)
KNOWN_CALLSIGN = re.compile(r"^GS-?\d+$", re.IGNORECASE)
CONFIRM_OBS = 3          # observations needed before a profile counts as confirmed
BLOCKLIST_RISK_MIN = 60  # risk a confirmed profile needs to be a blocklist candidate


def synthetic_location(key: str) -> dict:
    h = int(hashlib.sha256(key.encode()).hexdigest()[:8], 16)
    return {"lat": round(-55 + (h % 11000) / 100.0, 2),
            "lon": round(-180 + ((h >> 12) % 36000) / 100.0, 2),
            "err_km": 800, "synthetic": True}


def build_state(con) -> dict:
    rows = con.execute("SELECT * FROM packets ORDER BY ts").fetchall()
    feed = [{
        "ts": r["ts"], "src": r["src"], "cmd": r["cmd"], "modulation": "GFSK",
        "freq_dev_khz": r["freq_dev_khz"], "dop_hz": r["dop_hz"],
        "rssi": r["rssi"], "crc_ok": bool(r["crc_ok"]),
        "score": r["score"], "cls": r["cls"],
        "flagged": bool(r["flagged"]),
        "verdict": "block" if r["flagged"] else "accept",
    } for r in rows[-200:]]

    # One profile per claimed callsign — see the module docstring for why the
    # per-record `fp` hash cannot be used to group traffic.
    groups: dict[str, list] = {}
    for r in rows:
        groups.setdefault(r["src"] or "UNKNOWN", []).append(r)

    profiles = []
    for src, rs in groups.items():
        n = len(rs)
        commands: dict[str, int] = {}
        for r in rs:
            commands[r["cmd"]] = commands.get(r["cmd"], 0) + 1
        n_flag = sum(1 for r in rs if r["flagged"])
        susp_ratio = sum(1 for r in rs if r["cmd"] in SUSP_CMDS) / n
        mean_dev = sum(abs(r["freq_dev_khz"]) for r in rs) / n
        unknown = KNOWN_CALLSIGN.match(src) is None
        severity = (30 * (n_flag / n) + 25 * susp_ratio
                    + 20 * (1.0 if unknown else 0.0)
                    + 15 * min(1, n / 20)
                    + 10 * min(1, mean_dev / 20))
        confirmed = n >= CONFIRM_OBS
        risk = round(min(100.0, severity * min(1.0, n / CONFIRM_OBS)))
        profiles.append({
            "id": src, "risk": risk, "count": n, "flagged": n_flag,
            "confirmed": confirmed,
            "blocklist_candidate": confirmed and risk >= BLOCKLIST_RISK_MIN,
            "first_seen": rs[0]["ts"], "last_seen": rs[-1]["ts"],
            "max_score": max(r["score"] for r in rs),
            "mean_freq_dev_khz": round(mean_dev, 2),
            "commands": commands,
            "unknown_callsign": unknown,
            # record identifiers, newest first — one per packet by construction
            "fingerprints": [r["fp"] for r in reversed(rs) if r["fp"]][:8],
            "location": synthetic_location(src),
        })
    profiles.sort(key=lambda a: (-a["risk"], -a["count"]))

    n_flagged = sum(1 for r in rows if r["flagged"])
    alerts = cti_engine.alert_summary(con)
    return {
        "kpis": {
            "packets": len(rows),
            "flagged": n_flagged,
            "sources": len(profiles),
            "candidates": sum(1 for a in profiles if a["blocklist_candidate"]),
            "alerts_open": alerts.get("open", 0),
            "alerts_critical": alerts.get("critical", 0),
            "window_s": round(rows[-1]["ts"] - rows[0]["ts"], 1) if rows else 0,
        },
        "alerts": alerts,
        "profiles": profiles,
        "feed": list(reversed(feed)),
    }


# ── CRUD (db.html) ───────────────────────────────────────────────────────

# fields the DB page may edit, with their types
EDITABLE = {"src": str, "cmd": str, "freq_dev_khz": float, "dop_hz": float,
            "rssi": float, "crc_ok": int, "gap_s": float, "score": int,
            "fuzzy": float, "cls": str, "flagged": int, "conf": float, "fp": str}


def list_packets(con) -> list[dict]:
    rows = con.execute("SELECT * FROM packets ORDER BY ts DESC").fetchall()
    return [dict(r) for r in rows]


def update_packet(con, pid: int, fields: dict) -> bool:
    sets, vals = [], []
    for k, typ in EDITABLE.items():
        if k in fields:
            sets.append(f"{k}=?")
            vals.append(typ(fields[k]))
    if not sets:
        return False
    vals.append(pid)
    cur = con.execute(f"UPDATE packets SET {','.join(sets)} WHERE id=?", vals)
    con.commit()
    return cur.rowcount > 0


# ── http ─────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    con = None  # set by main()

    def log_message(self, *a):
        pass

    def _send(self, body: bytes, ctype: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(json.dumps(obj).encode(), "application/json", code)

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _query(self) -> dict:
        if "?" not in self.path:
            return {}
        out = {}
        for part in self.path.split("?", 1)[1].split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k] = v.replace("%20", " ").replace("+", " ")
        return out

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        if route == "/api/state":
            self._json(build_state(self.con))
            return
        if route == "/api/packets":
            self._json(list_packets(self.con))
            return
        if route == "/api/alerts":
            q = self._query()
            self._json({"alerts": cti_engine.list_alerts(self.con, q.get("status")),
                        "summary": cti_engine.alert_summary(self.con),
                        "rules": list(cti_engine.RULE_INDEX.values())})
            return
        if route == "/api/indicators":
            self._json({"indicators": cti_engine.indicators(self.con)})
            return
        if route == "/api/attribution":
            self._json(cti_engine.attribution(self.con))
            return
        if route == "/api/timeseries":
            self._json(cti_engine.timeseries(self.con))
            return
        if route == "/api/policy":
            self._json(cti_engine.policy(self.con))
            return
        if route.startswith("/api/analysis/"):
            try:
                pid = int(route.rsplit("/", 1)[1])
            except ValueError:
                self._json({"err": "bad id"}, 400)
                return
            res = cti_engine.packet_analysis(self.con, pid)
            self._json(res or {"err": "not found"}, 200 if res else 404)
            return
        if route.startswith("/api/export/"):
            kind = route.rsplit("/", 1)[1]
            try:
                minc = int(self._query().get("min_confidence", 50))
            except ValueError:
                minc = 50
            if kind == "stix":
                body = json.dumps(cti_engine.export_stix(self.con, minc), indent=2)
                self._send(body.encode(), "application/json")
            elif kind == "misp":
                body = json.dumps(cti_engine.export_misp(self.con, minc), indent=2)
                self._send(body.encode(), "application/json")
            elif kind == "csv":
                self._send(cti_engine.export_csv(self.con, minc).encode(),
                           "text/csv")
            else:
                self._json({"err": "unknown export"}, 404)
            return
        name = {"/": "index.html"}.get(self.path, self.path.lstrip("/"))
        path = os.path.normpath(os.path.join(WEB, name))
        if not path.startswith(WEB) or not os.path.isfile(path):
            self._send(b"not found", "text/plain", 404)
            return
        ctype = {".html": "text/html; charset=utf-8",
                 ".css": "text/css", ".js": "text/javascript"}.get(
            os.path.splitext(path)[1], "application/octet-stream")
        with open(path, "rb") as f:
            self._send(f.read(), ctype)

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        if route == "/api/analyse":
            n = analyse_ground(self.con)
            self._json({"ok": True, "records": n})
            return
        if route.startswith("/api/alert/"):
            try:
                aid = int(route.rsplit("/", 1)[1])
                status = json.loads(self._body() or b"{}").get("status", "")
            except (ValueError, json.JSONDecodeError):
                self._json({"ok": False, "err": "bad request"}, 400)
                return
            ok = cti_engine.set_alert_status(self.con, aid, status)
            self._json({"ok": ok}, 200 if ok else 400)
            return
        if route == "/api/indicator":
            try:
                b = json.loads(self._body() or b"{}")
            except json.JSONDecodeError:
                self._json({"ok": False, "err": "bad request"}, 400)
                return
            ok = cti_engine.set_indicator_status(
                self.con, b.get("value", ""), b.get("status", ""),
                b.get("note", ""))
            self._json({"ok": ok}, 200 if ok else 400)
            return
        if self.path == "/api/reset":
            self.con.execute("DELETE FROM packets")
            self.con.execute("DELETE FROM alerts")
            self.con.commit()
            self._json({"ok": True, "packets": 0})
            return
        if self.path.startswith("/api/packet/"):
            try:
                pid = int(self.path.rsplit("/", 1)[1])
                fields = json.loads(self._body() or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._json({"ok": False, "err": "bad request"}, 400)
                return
            if update_packet(self.con, pid, fields):
                self._json({"ok": True})
            else:
                self._json({"ok": False, "err": "not found or no editable fields"}, 404)
            return
        self._json({"ok": False, "err": "not found"}, 404)

    def do_DELETE(self):
        if self.path.startswith("/api/packet/"):
            try:
                pid = int(self.path.rsplit("/", 1)[1])
            except ValueError:
                self._json({"ok": False, "err": "bad id"}, 400)
                return
            cur = self.con.execute("DELETE FROM packets WHERE id=?", (pid,))
            self.con.commit()
            self._json({"ok": cur.rowcount > 0})
            return
        self._json({"ok": False, "err": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--radio", nargs="?", const=GS_PI_BIN, metavar="BIN",
                     help="run the Pi ground-station receiver (default "
                          "../gs_cti_pi/build/gs_cti_pi) and read its records")
    src.add_argument("--serial", help="Pico serial port, e.g. /dev/ttyACM0")
    src.add_argument("--simulate", action="store_true",
                     help="no hardware: drive the portal from cti_platform")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--rssi-threshold", type=float, default=None,
                    help="--radio only: AFC/AGC start threshold in dBm "
                         "(receiver default: noise floor + 15 dB)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="portal bind address; 0.0.0.0 to reach it from the LAN")
    ap.add_argument("--port", type=int, default=8700)
    ap.add_argument("--n", type=int, default=150, help="simulated packet count")
    ap.add_argument("--reset", action="store_true", help="wipe the database first")
    ap.add_argument("--analyse", action="store_true",
                    help="re-run the ground Doppler analysis over stored records and exit")
    args = ap.parse_args()

    if args.reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = db_connect()
    Handler.con = con

    if args.analyse:
        analyse_ground(con)
        return

    if not (args.radio or args.serial or args.simulate):
        ap.error("one of --radio, --serial, --simulate or --analyse is required")

    if args.simulate:
        ingest_simulate(con, args.n)
    elif args.radio:
        threading.Thread(target=ingest_radio,
                         args=(con, args.radio, args.rssi_threshold), daemon=True).start()
    else:
        threading.Thread(target=ingest_serial,
                         args=(con, args.serial, args.baud), daemon=True).start()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[server] portal: http://{args.host}:{args.port}  (db: {DB_PATH})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
