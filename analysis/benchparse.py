"""Shared parsing for the bench logs.

A bench log (benchlog.py) is JSON: {"pico": [[t, line], ...], "node": [[t, line], ...]}
with host timestamps t in seconds. Frames are matched between the transmitter
and a receiver by callsign, command and time.
"""
import json
import re

# uplink_transmitter: [up] t= 11.1s GS102  -> HNY1  HK_DUMP  foff= -4.0 kHz  dop= +5985 Hz  legit  sent
UP = re.compile(r"\[up\] t=\s*([\d.]+)s (\S+)\s+-> HNY1\s+(\S+)\s+foff=\s*([+-][\d.]+) kHz"
                r"\s+dop=\s*([+-]?\d+) Hz\s+(.*?)\s+(FCS-BROKEN )?sent")
# link_test:          [lt] seq=12 off=+24 len=29 sent
LT = re.compile(r"\[lt\] seq=(\d+) off=([+-]?\d+)")
# honeypot, honeypot mode:  [rx] GS104  PING  dev=  +5.8 res=  -0.2 dop= -153Hz rssi=-50 score= 0 known  WL-OK
RX = re.compile(r"\[rx\] (\S+)\s+(\S+)\s+dev=\s*([+-][\d.]+) res=\s*([+-][\d.]+) dop=\s*([+-]?\d+)Hz"
                r" rssi=\s*(-?\d+) score=\s*(\d+) (\w+)\s*(.*)")
# honeypot, member mode:  [mbr] UNK968 REBOOT  dev=+27.8kHz wl=none -> BLOCK (blocklist)
MB = re.compile(r"\[mbr\] (\S+)\s+(\S+)\s+dev=\s*([+-][\d.]+)kHz wl=(\S+) -> (\S+)\s*(.*)")


def load(path):
    with open(path) as f:
        ev = json.load(f)
    ev.setdefault("node", ev.pop("esp", []))      # older logs used "esp"
    return ev


def tx_frames(ev):
    """Frames the scenario transmitter logged, one per [up] line."""
    out, seen = [], set()
    for t, l in ev["pico"]:
        m = UP.search(l)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            out.append(dict(t=t, src=m.group(2), cmd=m.group(3), foff=float(m.group(4)),
                            dop=int(m.group(5)), what=m.group(6).strip()))
    # a frame logged in the last two seconds may not have reached the receiver log
    if ev["pico"]:
        out = [f for f in out if f["t"] < ev["pico"][-1][0] - 2]
    return out


def node_lines(ev, pattern):
    """Receiver lines matching pattern; an identical line repeated within 0.2 s
    is the USB passthrough duplicating output, not a second frame."""
    out, last = [], {}
    for t, l in ev["node"]:
        m = pattern.search(l)
        if m and not (l in last and t - last[l] < 0.2):
            last[l] = t
            out.append((t, m))
    return out


def match(frames, lines, key=lambda m: (m.group(1), m.group(2)), window=(-1.0, 2.5)):
    """Attach to each transmitted frame the first unused receiver line with the
    same callsign and command that appeared within the window after it."""
    used = set()
    for f in frames:
        for i, (t, m) in enumerate(lines):
            if i in used or key(m) != (f["src"], f["cmd"]):
                continue
            if window[0] < t - f["t"] < window[1]:
                f["rx"] = m
                used.add(i)
                break
    return frames
