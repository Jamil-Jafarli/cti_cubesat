#!/usr/bin/env python3
"""Analysis engine behind the CTI portal: detections, indicators, sharing.

hny_server.py owns ingestion, the packet table and the HTTP layer. Everything
that turns those packets into something an analyst acts on lives here:

  fuzzy_breakdown()   why the onboard classifier called a packet known /
                      suspicious / attacker — the §4.2 registry match with its
                      three weighted terms, the runner-up and the margin, so
                      the number in the record can be argued with instead of
                      trusted.
  evaluate()          the detection rules. One alert per (rule, packet) or per
                      (rule, source, window) for the aggregate ones, so a rerun
                      over the same data adds nothing.
  indicators()        what the bench is prepared to share: callsigns, RF
                      signatures and commands, each with a confidence, a TLP
                      marking and the evidence count behind it.
  export_stix() / export_misp() / export_csv()
                      the same indicator set in the three forms another
                      platform can read.

Nothing here writes to `packets`: the ground analysis in hny_server.py owns
those columns. Alerts and indicators are derived state and can be rebuilt from
the packet table at any time.

Only the standard library is used.
"""
from __future__ import annotations

import csv
import io
import json
import math
import re
import time
import uuid

# ── the onboard registry, mirrored ───────────────────────────────────────
# HnyProto.h REGISTRY / weights / thresholds. The whole point of duplicating
# them is to be able to recompute the onboard verdict on the ground and show
# the working; if the firmware table changes, this one has to follow.
REGISTRY = [
    ("GS100", 0.64, 0.04), ("GS101", -0.82, 0.11), ("GS102", 0.41, 0.06),
    ("GS103", -0.52, 0.09), ("GS104", 0.88, 0.03), ("GS105", -0.23, 0.07),
    ("GS106", 0.19, 0.12), ("GS107", -0.71, 0.05), ("GS108", 0.29, 0.08),
    ("GS109", 0.81, 0.02), ("GS110", -0.35, 0.10), ("GS111", 0.51, 0.06),
    ("GS112", -0.93, 0.04), ("GS113", 0.12, 0.09), ("GS114", -0.59, 0.11),
    ("GS115", 0.76, 0.05),
]
W_FREQ, W_DRIFT, W_MOD = 0.45, 0.25, 0.30
FUZZY_KNOWN_MIN, FUZZY_SUSP_MIN = 0.85, 0.60
FREQ_SPAN_KHZ = 25.0          # the 1 - |Δf|/25 term's normaliser
DRIFT_SPAN_PPM = 1.0

# Policy the member board enforces (HnyProto.h ALLOWLIST / BLOCKLIST). Shown in
# the portal so the ground picture and the onboard behaviour can be compared.
ONBOARD_ALLOWLIST = ["GS104"]
ONBOARD_BLOCKLIST = [
    {"call": "UNK968", "bias_khz": 28.0, "tol_khz": 2.0, "conf": 91.0},
    {"call": "UNK971", "bias_khz": 24.0, "tol_khz": 2.0, "conf": 88.0},
    {"call": "GS104", "bias_khz": 0.0, "tol_khz": 2.0, "conf": 85.0},
]
BLOCK_CONF_MIN = 80.0

SUSP_CMDS = ("REBOOT", "OVERRIDE", "0x7F_UNKNOWN_OPCODE", "ERASE_FLASH",
             "SET_MODE=DEBUG", "DISABLE_COMMS")
DESTRUCTIVE_CMDS = ("ERASE_FLASH", "DISABLE_COMMS", "OVERRIDE")
KNOWN_CALLSIGN = re.compile(r"^GS-?\d+$", re.IGNORECASE)

TLP_AMBER = "TLP:AMBER"
TLP_GREEN = "TLP:GREEN"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE,             -- (rule, packet) or (rule, entity, window)
  ts REAL NOT NULL,            -- when the evidence was captured, not analysed
  rule TEXT NOT NULL,
  severity TEXT NOT NULL,      -- critical | high | medium | low
  tactic TEXT,                 -- ATT&CK tactic name, for grouping only
  entity TEXT,                 -- the callsign the alert is about
  packet_id INTEGER,
  title TEXT,
  detail TEXT,                 -- JSON: the numbers the rule fired on
  status TEXT DEFAULT 'open'   -- open | ack | closed
);
CREATE TABLE IF NOT EXISTS indicator_state (
  value TEXT PRIMARY KEY,      -- indicator value, e.g. a callsign
  status TEXT,                 -- watch | blocklist | allowlist | dismissed
  note TEXT,
  updated REAL
);
"""

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ── fuzzy attribution ────────────────────────────────────────────────────

def fuzzy_breakdown(freq_dev_khz: float, drift_ppm: float = 0.0) -> dict:
    """Recompute the onboard §4.2 match and show every term.

    The bench cannot measure oscillator drift, so the firmware passes 0 and the
    drift term becomes a constant per registry entry. That is worth seeing: it
    means roughly a third of the score is carried by a figure this hardware
    never measured, and the ranking is decided by the carrier offset alone.
    """
    cands = []
    for call, bias, drift in REGISTRY:
        sf = max(0.0, 1.0 - abs(freq_dev_khz - bias) / FREQ_SPAN_KHZ)
        sd = max(0.0, 1.0 - abs(drift_ppm - drift) / DRIFT_SPAN_PPM)
        score = W_FREQ * sf + W_DRIFT * sd + W_MOD * 1.0
        cands.append({
            "id": call, "bias_khz": bias, "drift_ppm": drift,
            "delta_khz": round(freq_dev_khz - bias, 2),
            "freq_term": round(W_FREQ * sf, 4),
            "drift_term": round(W_DRIFT * sd, 4),
            "mod_term": round(W_MOD, 4),
            "score": round(score, 4),
        })
    cands.sort(key=lambda c: -c["score"])
    best, runner = cands[0], cands[1]
    cls = ("known" if best["score"] >= FUZZY_KNOWN_MIN
           else "suspicious" if best["score"] >= FUZZY_SUSP_MIN else "attacker")
    return {
        "best": best,
        "runner_up": runner,
        "margin": round(best["score"] - runner["score"], 4),
        "cls": cls,
        "thresholds": {"known": FUZZY_KNOWN_MIN, "suspicious": FUZZY_SUSP_MIN},
        "weights": {"freq": W_FREQ, "drift": W_DRIFT, "modulation": W_MOD},
        "ranked": cands[:5],
        "drift_measured": False,
    }


def signature(src: str, freq_dev_khz: float, bucket_khz: float = 0.5) -> str:
    """The transmitter signature the firmware whitelists on: claimed callsign
    plus the carrier offset quantised into half-kHz buckets. Unlike the record
    hash it survives from one packet to the next, which is what makes it
    usable as an identity at all (paper §4.3)."""
    q = round(freq_dev_khz / bucket_khz) * bucket_khz
    return f"{(src or '?').upper()}@{q:+.1f}"


# ── detection rules ──────────────────────────────────────────────────────
# Each rule reads one packet row plus the context dict the caller builds once
# (per-source statistics). Returning None means "did not fire".

def _d(row, key, default=None):
    try:
        v = row[key]
    except (IndexError, KeyError):
        return default
    return default if v is None else v


def rule_off_frequency(row, ctx):
    dev = _d(row, "freq_dev_khz", 0.0)
    if abs(dev) <= 20.0:
        return None
    return ("high", f"Carrier {dev:+.1f} kHz off the channel centre",
            {"freq_dev_khz": dev, "threshold_khz": 20.0})


def rule_doppler_residual(row, ctx):
    resid = _d(row, "dop_hz", 0.0)
    if abs(resid) <= 700.0:
        return None
    return ("high", f"Doppler residual {resid:+.0f} Hz — transmitter is not "
            f"tracking the satellite",
            {"dop_hz": resid, "threshold_hz": 700.0,
             "pass_t_s": _d(row, "pass_t_s")})


def rule_callsign_spoof(row, ctx):
    """A registered callsign whose carrier does not move with the pass. A real
    station pre-compensates Doppler; a fixed ground transmitter cannot, so the
    residual gives the impersonation away even when every other field is
    correct (paper §4.3, the case the RF fingerprinting is aimed at)."""
    src = (_d(row, "src", "") or "").upper()
    if not KNOWN_CALLSIGN.match(src):
        return None
    resid = _d(row, "dop_hz", 0.0)
    if abs(resid) <= 700.0:
        return None
    return ("critical", f"{src} claimed by a transmitter that is not tracking "
            f"the pass (residual {resid:+.0f} Hz)",
            {"dop_hz": resid, "claimed": src,
             "onboard_whitelist": _d(row, "wl")})


def rule_whitelist_mismatch(row, ctx):
    """The board's own answer to the same question, made before the packet was
    ever downlinked: the callsign is on the onboard whitelist but the RF
    signature it arrived with is not the enrolled one."""
    if _d(row, "wl") != 2:
        return None
    return ("critical", f"Onboard whitelist mismatch for {_d(row, 'src', '?')} "
            f"— signature {_d(row, 'sig', '?')}",
            {"sig": _d(row, "sig"), "src": _d(row, "src")})


def rule_suspicious_command(row, ctx):
    cmd = (_d(row, "cmd", "") or "")
    if cmd.upper() not in {c.upper() for c in SUSP_CMDS}:
        return None
    sev = "critical" if cmd.upper() in {c.upper() for c in DESTRUCTIVE_CMDS} else "medium"
    return (sev, f"Command {cmd} from {_d(row, 'src', '?')}",
            {"cmd": cmd, "destructive": sev == "critical"})


def rule_unregistered_source(row, ctx):
    src = _d(row, "src", "") or ""
    if KNOWN_CALLSIGN.match(src):
        return None
    return ("medium", f"{src} is not in the ground-station registry",
            {"src": src, "packets_from_source": ctx["counts"].get(src, 1)})


def rule_probing_burst(row, ctx):
    gap = _d(row, "gap_s")
    if gap is None or gap >= 2.0:
        return None
    return ("medium", f"Frame {gap:.2f} s after the previous one — probing rate",
            {"gap_s": gap, "threshold_s": 2.0})


def rule_malformed(row, ctx):
    if _d(row, "crc_ok", 1):
        return None
    return ("low", "Malformed frame: AX.25 FCS does not verify",
            {"crc_ok": 0})


PACKET_RULES = [
    ("RF-01", "Off-frequency carrier", "Initial Access", rule_off_frequency),
    ("RF-02", "Doppler residual anomaly", "Initial Access", rule_doppler_residual),
    ("ID-01", "Callsign impersonation", "Defense Evasion", rule_callsign_spoof),
    ("ID-02", "Onboard whitelist mismatch", "Defense Evasion", rule_whitelist_mismatch),
    ("CMD-01", "Suspicious command", "Execution", rule_suspicious_command),
    ("REC-01", "Unregistered source", "Reconnaissance", rule_unregistered_source),
    ("REC-02", "Probing burst", "Reconnaissance", rule_probing_burst),
    ("INT-01", "Malformed frame", "Defense Evasion", rule_malformed),
]

CAMPAIGN_WINDOW_S = 600.0
CAMPAIGN_MIN_FLAGGED = 5

RULE_INDEX = {rid: {"id": rid, "name": name, "tactic": tactic}
              for rid, name, tactic, _ in PACKET_RULES}
RULE_INDEX["AGG-01"] = {"id": "AGG-01", "name": "Sustained campaign",
                        "tactic": "Impact"}


def evaluate(con) -> int:
    """Run every rule over the packet table. Returns the number of NEW alerts.

    Idempotent by construction: each alert carries a key built from the rule and
    what it fired on, and the insert ignores duplicates. Re-running after the
    ground analysis has rewritten scores therefore adds only what changed.
    """
    rows = con.execute("SELECT * FROM packets ORDER BY ts").fetchall()
    if not rows:
        return 0

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["src"] or "?"] = counts.get(r["src"] or "?", 0) + 1
    ctx = {"counts": counts}

    new = 0
    for r in rows:
        for rid, name, tactic, fn in PACKET_RULES:
            hit = fn(r, ctx)
            if not hit:
                continue
            severity, title, detail = hit
            key = f"{rid}:{r['id']}"
            new += _insert_alert(con, key, r["ts"], rid, severity, tactic,
                                 r["src"], r["id"], title, detail)

    # Aggregate rule: flagged traffic from one source inside a window. Keyed by
    # the window start so a long campaign produces one alert per window rather
    # than one per packet.
    buckets: dict[tuple, list] = {}
    for r in rows:
        if not r["flagged"]:
            continue
        w = int(r["ts"] // CAMPAIGN_WINDOW_S)
        buckets.setdefault((r["src"] or "?", w), []).append(r)
    for (src, w), rs in buckets.items():
        if len(rs) < CAMPAIGN_MIN_FLAGGED:
            continue
        key = f"AGG-01:{src}:{w}"
        cmds = sorted({r["cmd"] for r in rs if r["cmd"]})
        new += _insert_alert(
            con, key, rs[0]["ts"], "AGG-01", "critical", "Impact", src,
            rs[-1]["id"],
            f"{len(rs)} flagged frames from {src} within "
            f"{int(CAMPAIGN_WINDOW_S / 60)} minutes",
            {"flagged": len(rs), "commands": cmds,
             "window_start": w * CAMPAIGN_WINDOW_S})
    con.commit()
    return new


def _insert_alert(con, key, ts, rule, severity, tactic, entity, packet_id,
                  title, detail) -> int:
    cur = con.execute(
        "INSERT OR IGNORE INTO alerts (key, ts, rule, severity, tactic, entity,"
        " packet_id, title, detail) VALUES (?,?,?,?,?,?,?,?,?)",
        (key, ts, rule, severity, tactic, entity, packet_id, title,
         json.dumps(detail)))
    return cur.rowcount


def list_alerts(con, status: str | None = None, limit: int = 300) -> list[dict]:
    q = "SELECT * FROM alerts"
    args: list = []
    if status and status != "all":
        q += " WHERE status=?"
        args.append(status)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    out = []
    for r in con.execute(q, args):
        d = dict(r)
        d["detail"] = json.loads(d["detail"] or "{}")
        d["rule_name"] = RULE_INDEX.get(d["rule"], {}).get("name", d["rule"])
        out.append(d)
    out.sort(key=lambda a: (SEV_ORDER.get(a["severity"], 9), -a["ts"]))
    return out


def set_alert_status(con, alert_id: int, status: str) -> bool:
    if status not in ("open", "ack", "closed"):
        return False
    cur = con.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
    con.commit()
    return cur.rowcount > 0


def alert_summary(con) -> dict:
    out = {"open": 0, "ack": 0, "closed": 0,
           "critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in con.execute("SELECT status, severity, COUNT(*) n FROM alerts "
                         "GROUP BY status, severity"):
        out[r["status"]] = out.get(r["status"], 0) + r["n"]
        if r["status"] != "closed":
            out[r["severity"]] = out.get(r["severity"], 0) + r["n"]
    return out


# ── indicators ───────────────────────────────────────────────────────────

def _confidence(count: int, flagged: int, consistency: float) -> int:
    """Confidence an indicator deserves: how much evidence, how much of it is
    flagged, and how tightly the carrier offsets cluster. Capped below 100 —
    a bench of two radios cannot earn certainty."""
    evidence = min(1.0, count / 10.0)
    ratio = flagged / count if count else 0.0
    return int(round(min(95.0, 40 * evidence + 35 * ratio + 25 * consistency)))


def indicators(con) -> list[dict]:
    rows = con.execute("SELECT * FROM packets ORDER BY ts").fetchall()
    overrides = {r["value"]: dict(r)
                 for r in con.execute("SELECT * FROM indicator_state")}
    tactics: dict[str, set] = {}
    for a in con.execute("SELECT entity, tactic FROM alerts"):
        if a["entity"]:
            tactics.setdefault(a["entity"], set()).add(a["tactic"])

    by_call: dict[str, list] = {}
    by_sig: dict[str, list] = {}
    by_cmd: dict[str, list] = {}
    for r in rows:
        src = (r["src"] or "?").upper()
        by_call.setdefault(src, []).append(r)
        by_sig.setdefault(r["sig"] or signature(src, r["freq_dev_khz"] or 0.0),
                          []).append(r)
        if (r["cmd"] or "").upper() in {c.upper() for c in SUSP_CMDS}:
            by_cmd.setdefault(r["cmd"], []).append(r)

    out: list[dict] = []

    def add(kind, value, rs, extra=None):
        n = len(rs)
        flagged = sum(1 for r in rs if r["flagged"])
        devs = [r["freq_dev_khz"] or 0.0 for r in rs]
        mean = sum(devs) / n
        spread = math.sqrt(sum((d - mean) ** 2 for d in devs) / n) if n > 1 else 0.0
        consistency = max(0.0, 1.0 - spread / 5.0)     # 5 kHz spread → 0
        st = overrides.get(value, {})
        # a signature inherits its callsign's disposition: "UNK968@+28.0" is the
        # same transmitter as "UNK968" and should not read as unrelated
        base = value.split("@")[0]
        default_status = "allowlist" if base in ONBOARD_ALLOWLIST else (
            "blocklist" if any(b["call"] == base for b in ONBOARD_BLOCKLIST)
            else "watch")
        out.append({
            "type": kind,
            "value": value,
            "count": n,
            "flagged": flagged,
            "first_seen": rs[0]["ts"],
            "last_seen": rs[-1]["ts"],
            "mean_freq_dev_khz": round(mean, 2),
            "spread_khz": round(spread, 2),
            "confidence": _confidence(n, flagged, consistency),
            "tlp": TLP_AMBER if flagged else TLP_GREEN,
            "tactics": sorted(tactics.get(value.split("@")[0], [])),
            "status": st.get("status") or default_status,
            "note": st.get("note") or "",
            "commands": sorted({r["cmd"] for r in rs if r["cmd"]})[:8],
            **(extra or {}),
        })

    for call, rs in by_call.items():
        add("callsign", call, rs,
            {"registered": bool(KNOWN_CALLSIGN.match(call))})
    for sig, rs in by_sig.items():
        if len(rs) < 2:            # one packet is not yet a signature
            continue
        add("rf-signature", sig, rs)
    for cmd, rs in by_cmd.items():
        add("command", cmd, rs,
            {"destructive": cmd.upper() in {c.upper() for c in DESTRUCTIVE_CMDS}})

    out.sort(key=lambda i: (-i["confidence"], -i["count"]))
    return out


def set_indicator_status(con, value: str, status: str, note: str = "") -> bool:
    if status not in ("watch", "blocklist", "allowlist", "dismissed"):
        return False
    con.execute(
        "INSERT INTO indicator_state (value, status, note, updated) VALUES (?,?,?,?)"
        " ON CONFLICT(value) DO UPDATE SET status=excluded.status,"
        " note=excluded.note, updated=excluded.updated",
        (value, status, note, time.time()))
    con.commit()
    return True


# ── sharing ──────────────────────────────────────────────────────────────

def _stix_pattern(ind: dict) -> str:
    v = ind["value"].replace("'", "")
    if ind["type"] == "callsign":
        return f"[x-radio-frame:callsign = '{v}']"
    if ind["type"] == "command":
        return f"[x-radio-frame:command = '{v}']"
    call, _, off = v.partition("@")
    return (f"[x-radio-frame:callsign = '{call}' AND "
            f"x-radio-frame:carrier_offset_khz = '{off}']")


def export_stix(con, min_confidence: int = 50) -> dict:
    """STIX 2.1 bundle. The RF properties have no standard object type, so they
    are carried as x-radio-frame custom properties: readable by any STIX
    parser, and honest about being an extension rather than pretending a
    satellite uplink is a network indicator."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    marking = {
        "type": "marking-definition", "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp", "name": TLP_AMBER,
        "definition": {"tlp": "amber"},
    }
    objects = [marking, {
        "type": "identity", "spec_version": "2.1",
        "id": "identity--5b6f29fd-2a9c-4a37-9b33-6f0d1b1e77a1",
        "created": now, "modified": now,
        "name": "Honeypot CubeSat bench", "identity_class": "system",
        "description": "Onboard RF honeypot; records downlinked to a CTI "
                       "ground station (paper §3.1, §6.2).",
    }]
    for ind in indicators(con):
        if ind["confidence"] < min_confidence or ind["status"] == "dismissed":
            continue
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, ind['value'])}",
            "created": now, "modified": now,
            "created_by_ref": objects[1]["id"],
            "name": f"{ind['type']}: {ind['value']}",
            "description": (f"{ind['count']} frames, {ind['flagged']} flagged, "
                            f"mean carrier offset {ind['mean_freq_dev_khz']} kHz "
                            f"(spread {ind['spread_khz']} kHz)."),
            "indicator_types": ["anomalous-activity"],
            "pattern": _stix_pattern(ind),
            "pattern_type": "stix",
            "valid_from": time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                                        time.gmtime(ind["first_seen"])),
            "confidence": ind["confidence"],
            "labels": ind["tactics"] or ["uncategorised"],
            "object_marking_refs": [marking["id"]],
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def export_misp(con, min_confidence: int = 50) -> dict:
    now = time.strftime("%Y-%m-%d")
    attrs = []
    for ind in indicators(con):
        if ind["confidence"] < min_confidence or ind["status"] == "dismissed":
            continue
        attrs.append({
            "type": "other", "category": "Network activity",
            "value": f"{ind['type']}:{ind['value']}",
            "to_ids": ind["status"] == "blocklist",
            "comment": (f"{ind['count']} frames / {ind['flagged']} flagged / "
                        f"confidence {ind['confidence']}"),
            "Tag": [{"name": ind["tlp"].lower()}]
                   + [{"name": f"attck:{t.lower().replace(' ', '-')}"}
                      for t in ind["tactics"]],
        })
    return {"Event": {
        "info": "Honeypot CubeSat bench — uplink indicators",
        "date": now, "threat_level_id": "2", "analysis": "1",
        "distribution": "1", "Attribute": attrs,
    }}


def export_csv(con, min_confidence: int = 0) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "count", "flagged", "confidence", "tlp",
                "status", "mean_freq_dev_khz", "spread_khz", "tactics",
                "first_seen", "last_seen"])
    for i in indicators(con):
        if i["confidence"] < min_confidence:
            continue
        w.writerow([i["type"], i["value"], i["count"], i["flagged"],
                    i["confidence"], i["tlp"], i["status"],
                    i["mean_freq_dev_khz"], i["spread_khz"],
                    "|".join(i["tactics"]),
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(i["first_seen"])),
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(i["last_seen"]))])
    return buf.getvalue()


# ── views the portal needs ───────────────────────────────────────────────

def packet_analysis(con, packet_id: int) -> dict | None:
    r = con.execute("SELECT * FROM packets WHERE id=?", (packet_id,)).fetchone()
    if not r:
        return None
    row = dict(r)
    ctx = {"counts": {}}
    fired = []
    for rid, name, tactic, fn in PACKET_RULES:
        hit = fn(r, ctx)
        if hit:
            fired.append({"rule": rid, "name": name, "tactic": tactic,
                          "severity": hit[0], "title": hit[1], "detail": hit[2]})
    return {
        "packet": row,
        "fuzzy": fuzzy_breakdown(row.get("freq_dev_khz") or 0.0),
        "signature": row.get("sig") or signature(row.get("src") or "?",
                                                 row.get("freq_dev_khz") or 0.0),
        "rules_fired": fired,
        "onboard": {
            "score": row.get("onboard_score"),
            "cls": row.get("cls"),
            "whitelist": {0: "no entry", 1: "match", 2: "mismatch"}.get(
                row.get("wl"), "not reported"),
        },
    }


def timeseries(con, buckets: int = 40) -> dict:
    """Frames and flagged frames over the capture window, for the overview
    chart. Fixed bucket count so the shape stays readable whether the bench ran
    for two minutes or an hour."""
    rows = con.execute("SELECT ts, flagged, score FROM packets ORDER BY ts").fetchall()
    if not rows:
        return {"buckets": [], "bucket_s": 0}
    t0, t1 = rows[0]["ts"], rows[-1]["ts"]
    span = max(1.0, t1 - t0)
    step = span / buckets
    out = [{"t": t0 + i * step, "frames": 0, "flagged": 0, "score_sum": 0}
           for i in range(buckets)]
    for r in rows:
        i = min(buckets - 1, int((r["ts"] - t0) / step))
        out[i]["frames"] += 1
        out[i]["flagged"] += 1 if r["flagged"] else 0
        out[i]["score_sum"] += r["score"] or 0
    for b in out:
        b["mean_score"] = round(b["score_sum"] / b["frames"], 1) if b["frames"] else 0
        del b["score_sum"]
    return {"buckets": out, "bucket_s": round(step, 2)}


def attribution(con) -> dict:
    """Carrier-offset picture per callsign: where each source actually sits, how
    tightly, and what the onboard registry would call it. This is the view that
    separates 'a station with a known bias' from 'a transmitter parked on a
    fixed frequency pretending to be one'."""
    rows = con.execute("SELECT * FROM packets ORDER BY ts").fetchall()
    by: dict[str, list] = {}
    for r in rows:
        by.setdefault((r["src"] or "?").upper(), []).append(r)
    out = []
    for src, rs in by.items():
        devs = [r["freq_dev_khz"] or 0.0 for r in rs]
        resid = [r["dop_hz"] or 0.0 for r in rs]
        mean = sum(devs) / len(devs)
        spread = (math.sqrt(sum((d - mean) ** 2 for d in devs) / len(devs))
                  if len(devs) > 1 else 0.0)
        mean_abs_resid = sum(abs(x) for x in resid) / len(resid)
        fz = fuzzy_breakdown(mean)
        out.append({
            "src": src,
            "count": len(rs),
            "mean_freq_dev_khz": round(mean, 2),
            "spread_khz": round(spread, 2),
            "min_khz": round(min(devs), 2), "max_khz": round(max(devs), 2),
            "mean_abs_residual_hz": round(mean_abs_resid, 0),
            "tracks_pass": mean_abs_resid <= 700.0,
            "registry_match": fz["best"]["id"],
            "registry_score": fz["best"]["score"],
            "registry_cls": fz["cls"],
            "signatures": sorted({r["sig"] for r in rs if r["sig"]})[:6],
            "flagged": sum(1 for r in rs if r["flagged"]),
        })
    out.sort(key=lambda a: -a["count"])
    return {"sources": out, "registry": [
        {"id": c, "bias_khz": b, "drift_ppm": d} for c, b, d in REGISTRY]}


def policy(con) -> dict:
    """What the member board would enforce right now, next to what the ground
    picture says it should. The gap between the two is the operational
    question: the satellite only learns what has been uplinked to it."""
    inds = {i["value"]: i for i in indicators(con)}
    proposed = [v for v, i in inds.items()
                if i["type"] == "callsign" and i["status"] == "blocklist"]
    onboard = [b["call"] for b in ONBOARD_BLOCKLIST]
    return {
        "onboard_allowlist": ONBOARD_ALLOWLIST,
        "onboard_blocklist": ONBOARD_BLOCKLIST,
        "block_conf_min": BLOCK_CONF_MIN,
        "proposed_blocklist": sorted(proposed),
        "not_yet_uplinked": sorted(set(proposed) - set(onboard)),
        "stale_onboard": sorted(set(onboard) - set(proposed)),
    }
