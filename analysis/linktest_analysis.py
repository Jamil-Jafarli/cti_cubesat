#!/usr/bin/env python3
"""Link test: link_test_pico frames vs the honeypot, and optionally vs the
ground station, per carrier offset.

    python3 linktest_analysis.py linktest.json [--gs-log gs.log]

gs.log is the ground station's log for the same period, e.g.
    journalctl -u cti-server --since "<start>" --no-pager -q > gs.log
The ground station logs every uplink frame it decodes as
"ignoring frame LNKTST -> HNY1 ... info=<seq>|O<off>S<seq>".
"""
import argparse
import collections
import re
import statistics

import benchparse as bp


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("--gs-log")
    a = ap.parse_args()
    ev = bp.load(a.log)

    tx = {}
    for t, l in ev["pico"]:
        m = bp.LT.search(l)
        if m:
            tx[int(m.group(1)) % 10000] = int(m.group(2))
    seqs = sorted(tx)[1:-2]            # drop the frames cut by the log boundaries

    node = {}
    for t, l in ev["node"]:
        m = re.search(r"\[rx\] LNKTST\s+O([+-]\d+)S(\d{4})\s+dev=\s*([+-][\d.]+).*?rssi=\s*(-?\d+)", l)
        if m:
            node[int(m.group(2))] = (float(m.group(3)), int(m.group(4)))

    gs, gs_crc = {}, 0
    if a.gs_log:
        for l in open(a.gs_log, errors="replace"):
            m = re.search(r"ignoring frame LNKTST -> HNY1 rssi=(-?\d+) afc=([+-][\d.]+) "
                          r"info=\d+\|O([+-]\d+)S(\d{4})", l)
            if m:
                gs[int(m.group(4))] = (float(m.group(2)), int(m.group(1)))
            gs_crc += "PHY CRC failed" in l

    n = len(seqs)
    ne = sum(s in node for s in seqs)
    line = f"frames {n} | honeypot {ne} ({100 * ne / max(1, n):.0f}%)"
    if a.gs_log:
        ng = sum(s in gs for s in seqs)
        line += f" | ground station {ng} ({100 * ng / max(1, n):.0f}%), PHY-CRC drops {gs_crc}"
    print(line)

    by = collections.defaultdict(lambda: [0, 0, 0])
    for s in seqs:
        o = tx[s]
        by[o][0] += 1
        by[o][1] += s in node
        by[o][2] += s in gs
    for o in sorted(by):
        t_, e_, g_ = by[o]
        print(f"  offset {o:+3d} kHz: sent {t_:3d}  honeypot {e_:3d} ({100 * e_ / max(1, t_):3.0f}%)"
              + (f"  ground {g_:3d} ({100 * g_ / max(1, t_):3.0f}%)" if a.gs_log else ""))

    err = [node[s][0] - tx[s] for s in seqs if s in node]
    if err:
        print(f"  honeypot carrier-offset error {statistics.mean(err):+.2f} ± "
              f"{statistics.pstdev(err):.2f} kHz (n={len(err)}); a steady mean is a "
              f"calibration error: add it (in Hz) to CALIB_HZ in hny_node_esp32.ino")


if __name__ == "__main__":
    main()
