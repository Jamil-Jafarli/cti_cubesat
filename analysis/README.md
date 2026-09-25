# Reproducing the bench measurements

All scripts need Python 3 and `pyserial` (for logging). The transmitter Pico is on
`/dev/ttyACM*`, the honeypot on `/dev/ttyUSB0` (change with `--pico` / `--node`).

## 1. Link test and calibration

Flash `firmware/link_test_pico` (2 frames/s, sequence numbers, offsets 0, ±4, ±8, +24,
+28 kHz; send `1`–`9` to it for 100–900 ms spacing, `z` for 0 kHz only).

```
python3 benchlog.py --seconds 120 --out linktest.json
# on the Pi, for the same period:  journalctl -u cti-server --since "<start>" -q > gs.log
python3 linktest_analysis.py linktest.json --gs-log gs.log
```

Prints capture per offset for the honeypot and the ground station, and the honeypot's
carrier-offset error (add a steady mean to `CALIB_HZ`).

## 2. Radio power

On the honeypot's console type `P` (three times for repeatability) with the transmitter
silent. The JSON gives current, voltage and power on the radio rail for listening,
standby, sleep and a 2 dBm carrier.

## 3. End-to-end scenario run

Flash `firmware/gs_uplink_pico`. Start from an empty honeypot store (`E`) and an empty
ground database (stop the server, move `bench_cti.db` away, start it again).

```
python3 benchlog.py --seconds 900 --out run.json --node-cmd R    # 15 min uplink
# silence the transmitter, then type D on the honeypot; wait for "[dl] done"
# copy ground_station/server/bench_cti.db from the Pi to ground.db
python3 scenario_analysis.py run.json ground.db
```

Prints capture overall and per 3 minutes, per-scenario onboard and ground verdicts, the
carrier-offset error on Doppler-free frames, and the alerts per scenario. Type `S` on the
honeypot after the uplink for the timing, heap and stack figures.

## 4. Member mode

```
python3 benchlog.py --seconds 360 --out member.json --node-cmd M
python3 member_analysis.py member.json
# type M again to return the node to honeypot mode
```

Prints, per scenario, how many frames were heard and the accept/block verdicts with the
whitelist state.
