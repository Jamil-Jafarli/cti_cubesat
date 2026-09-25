#!/usr/bin/env python3
"""Log the transmitter Pico and the honeypot node side by side, with host
timestamps, for later matching (linktest_analysis.py, scenario_analysis.py,
member_analysis.py).

    python3 benchlog.py --seconds 900 --out run.json --node-cmd R
    python3 benchlog.py --seconds 360 --out member.json --node-cmd M

--node-cmd sends one serial command to the honeypot when logging starts
(R = reset the timing counters, M = toggle member mode). Needs pyserial.
"""
import argparse
import glob
import json
import threading
import time

import serial


def reader(name, port_fn, seconds, events, cmd=None):
    t0 = time.time()
    buf = b""
    while time.time() - t0 < seconds:
        try:
            with serial.Serial(port_fn(), 115200, timeout=0.2) as s:
                if cmd:
                    s.write(cmd.encode())
                    cmd = None
                while time.time() - t0 < seconds:
                    buf += s.read(4096)
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        events[name].append((time.time(), line.decode("utf-8", "replace").strip()))
        except (serial.SerialException, IndexError, OSError):
            time.sleep(0.5)          # board re-enumerating: try again


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seconds", type=float, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pico", help="transmitter port (default: first /dev/ttyACM*)")
    ap.add_argument("--node", default="/dev/ttyUSB0", help="honeypot port")
    ap.add_argument("--node-cmd", help="one serial command sent to the honeypot at start")
    a = ap.parse_args()

    pico = (lambda: a.pico) if a.pico else (lambda: sorted(glob.glob("/dev/ttyACM*"))[0])
    events = {"pico": [], "node": []}
    th = [threading.Thread(target=reader, args=("pico", pico, a.seconds, events)),
          threading.Thread(target=reader, args=("node", lambda: a.node, a.seconds, events,
                                                a.node_cmd))]
    for t in th:
        t.start()
    for t in th:
        t.join()
    with open(a.out, "w") as f:
        json.dump(events, f)
    print(f"{a.out}: {len(events['pico'])} transmitter lines, {len(events['node'])} honeypot lines")


if __name__ == "__main__":
    main()
