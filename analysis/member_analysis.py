#!/usr/bin/env python3
"""Member-mode run: transmitter log vs the honeypot's accept/block verdicts.

    python3 benchlog.py --seconds 360 --out member.json --node-cmd M
    python3 member_analysis.py member.json

(Send 'M' again afterwards to put the node back in honeypot mode.)
"""
import collections
import sys

import benchparse as bp


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    ev = bp.load(sys.argv[1])
    tx = bp.match(bp.tx_frames(ev), bp.node_lines(ev, bp.MB))
    heard = sum("rx" in f for f in tx)
    print(f"frames {len(tx)}, heard {heard} ({100 * heard / max(1, len(tx)):.0f}%)")
    out = collections.OrderedDict()
    for f in tx:
        k = f"{f['src']} {f['cmd']} ({f['what']})"
        o = out.setdefault(k, [0, 0, collections.Counter()])
        o[0] += 1
        if "rx" in f:
            m = f["rx"]
            o[1] += 1
            o[2][f"{m.group(5)} wl={m.group(4)} {m.group(6)}".strip()] += 1
    for k, (n, h, v) in out.items():
        print(f"  {k:48} heard {h}/{n}  {dict(v)}")


if __name__ == "__main__":
    main()
