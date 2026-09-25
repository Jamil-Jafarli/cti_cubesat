#!/usr/bin/env python3
"""End-to-end scenario run: transmitter log vs the honeypot's store as it
arrived at the ground station.

    python3 scenario_analysis.py run.json ground.db

run.json   benchlog.py output for the uplink (gs_uplink_pico on the Pico)
ground.db  the ground station's bench_cti.db after the downlink ('D')

Each ground record is matched to the frame the transmitter logged by
callsign, command and time (the honeypot's millis() clock is aligned to the
host clock by the most common offset), so capture is computed from the store
itself and does not depend on the honeypot's serial log. Prints capture,
onboard and ground verdicts and alerts per scenario.
"""
import collections
import json
import sqlite3
import statistics
import sys

import benchparse as bp

ORDER = ["legit", "freq+unknown+cmd", "callsign spoof", "probing burst",
         "doppler spoof", "malformed FCS"]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    ev = bp.load(sys.argv[1])
    tx = bp.tx_frames(ev)
    con = sqlite3.connect(sys.argv[2])
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM packets ORDER BY device_ms").fetchall()

    diffs = collections.Counter()
    for r in rows:
        for f in tx:
            if (f["src"], f["cmd"]) == (r["src"], r["cmd"]):
                diffs[round(f["t"] - r["device_ms"] / 1000.0)] += 1
    off = max(diffs, key=diffs.get) if diffs else 0

    used, scen_of = set(), {}
    for f in tx:
        best = None
        for r in rows:
            if r["id"] in used or (r["src"], r["cmd"]) != (f["src"], f["cmd"]):
                continue
            dt = abs(r["device_ms"] / 1000.0 + off - f["t"])
            if dt <= 2.0 and (best is None or dt < best[0]):
                best = (dt, r)
        if best:
            used.add(best[1]["id"])
            f["row"] = best[1]
            scen_of[best[1]["id"]] = f["what"]

    cap = sum("row" in f for f in tx)
    print(f"transmitted {len(tx)}, captured {cap} ({100 * cap / max(1, len(tx)):.1f}%), "
          f"ground records {len(rows)} ({len(rows) - len(used)} outside the logged window)")
    t0 = ev["pico"][0][0]
    win = collections.OrderedDict()
    for f in tx:
        k = int((f["t"] - t0) // 180)
        win.setdefault(k, [0, 0])
        win[k][0] += 1
        win[k][1] += "row" in f
    print("capture per 3 minutes:", ", ".join(f"{b}/{a}" for a, b in win.values()))

    print(f"{'scenario':18} {'captured':>9} {'onboard flag':>13} {'wl mismatch':>12} "
          f"{'malformed':>10} {'ground flag':>12}")
    for w in ORDER:
        fs = [f for f in tx if f["what"] == w]
        rs = [f["row"] for f in fs if "row" in f]
        print(f"{w:18} {len(rs):4}/{len(fs):<4} {sum((r['onboard_score'] or 0) >= 50 for r in rs):13} "
              f"{sum(r['wl'] == 2 for r in rs):12} {sum(not r['crc_ok'] for r in rs):10} "
              f"{sum(r['flagged'] or 0 for r in rs):12}")

    err = [f["row"]["freq_dev_khz"] - f["foff"] for f in tx if "row" in f and f["dop"] == 0]
    if err:
        print(f"carrier-offset error, Doppler-free frames: {statistics.mean(err):+.2f} ± "
              f"{statistics.pstdev(err):.2f} kHz, {sum(abs(e) <= 0.4 for e in err)}/{len(err)} "
              f"within ±0.4 kHz")

    alerts = collections.defaultdict(collections.Counter)
    for a in con.execute("SELECT rule, severity, packet_id FROM alerts"):
        alerts[scen_of.get(a["packet_id"], "other / aggregate")][f"{a['rule']}/{a['severity']}"] += 1
    print("alerts per scenario:")
    for w in ORDER + ["other / aggregate"]:
        if w in alerts:
            print(f"  {w:18} {json.dumps(dict(alerts[w]))}")


if __name__ == "__main__":
    main()
