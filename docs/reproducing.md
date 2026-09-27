# Reproducing the measurements

`data/2026-09-25-campaign/` holds the raw logs and the ground database of the
bench campaign of 25 September 2026. The scripts in `analysis/` turn them into
the published figures, and the same scripts work on your own logs.

The analysis scripts need Python 3.9+ and nothing else; only the logger
(`benchlog.py`) needs pyserial.

## From the bundled data

```sh
cd analysis
D=../data/2026-09-25-campaign

python3 scenario_analysis.py $D/scenario_run.json $D/ground.db
python3 member_analysis.py   $D/member_run.json
python3 linktest_analysis.py $D/linktest_900ms.json
python3 linktest_analysis.py $D/linktest_500ms.json
```

### End-to-end scenario run

A 15-minute run of `firmware/uplink_transmitter`. The honeypot started with an
empty store and the ground station with an empty database; afterwards the
transmitter was silenced and the honeypot downlinked its 148 stored records
(all 148 arrived without a CRC error, in each of two passes). Every ground
record is matched to the frame the transmitter logged, by callsign, command
and time.

```
transmitted 147, captured 128 (87.1%), ground records 148 (20 outside the logged window)
capture per 3 minutes: 32/32, 30/30, 31/32, 26/26, 9/27
scenario            captured  onboard flag  wl mismatch  malformed  ground flag
legit                63/72               0            3          0            0
freq+unknown+cmd     13/15              13            0          0           13
callsign spoof       14/16               0           12          0            0
probing burst        14/16              14            0          0           14
doppler spoof        12/13               0            0          0            0
malformed FCS        12/15               0            0         12            0
carrier-offset error, Doppler-free frames: -0.06 ± 0.20 kHz, 53/53 within ±0.4 kHz
alerts per scenario:
  legit              {"REC-02/medium": 13, "ID-02/critical": 3}
  freq+unknown+cmd   {"RF-01/high": 13, "RF-02/high": 13, "CMD-01/medium": 13, "REC-01/medium": 13}
  callsign spoof     {"RF-02/high": 14, "ID-01/critical": 14, "CMD-01/critical": 14, "ID-02/critical": 12}
  probing burst      {"RF-01/high": 14, "RF-02/high": 14, "CMD-01/medium": 14, "REC-01/medium": 14}
  doppler spoof      {"RF-02/high": 12, "ID-01/critical": 12}
  malformed FCS      {"INT-01/low": 12}
  other / aggregate  {...}
```

Reading it:

- Every attack record raised at least one alert, and the impersonations raised
  critical ones. No legitimate record was flagged.
- The score threshold (50) separates only the combined attacks; the
  single-indicator attacks are caught by the ground rules.
- The remaining alerts on legitimate records come from the indicator
  definitions: a 0.9 s burst is attributed to the frame after it (REC-02), and
  the onboard Doppler estimate lags the fastest part of the pass (three
  whitelist mismatches, ID-02).
- Capture was 119 of 120 frames for the first 12 minutes. In the last three
  minutes the bench was physically disturbed and capture fell to 9 of 27.
- "other / aggregate" holds the records outside the logged window and the two
  AGG-01 campaign alerts.

### Member mode

A 6-minute run with the honeypot in member mode (`M`), after the disturbance:
39 of 61 frames were heard. All 11 frames heard from blocklisted sources were
blocked, including the `GS104 ERASE_FLASH` impersonation (whitelist mismatch,
so the allowlist override was withheld). 22 of 23 legitimate frames were
accepted; the exception is one real `GS104 PING` whose estimated residual fell
outside the whitelist tolerance, the bench's one false block. The Doppler
spoof and the malformed frames were accepted, as they must be in a mode that
blocks only on the blocklist.

### Link test

`firmware/link_test` at seven carrier offsets, logged frame by frame:

| Frame interval | Honeypot | Honeypot carrier-offset error |
|---|---|---|
| 0.9 s | 75 of 77 (97 %) | −0.00 ± 0.24 kHz |
| 0.5 s | 22 of 247 (9 %) | +0.11 ± 2.34 kHz |

The ground station, logging the same frames as a reference receiver, decoded
all of them at both intervals (its log is not included). The honeypot
scores, fingerprints and writes each frame to flash (up to 154 ms) before it
listens again, so it cannot keep up with frames about twice a second.

### Processing time and power

`honeypot_status.json` is the honeypot's status report after the scenario run
(134 frames processed by then), `power.json` three runs of the power profile:

| Quantity | Value |
|---|---|
| scoring + fingerprint per frame, mean / max | 290 µs / 347 µs (x86_64 desktop: 195 µs) |
| flash write per frame, mean / max | 44.7 ms / 154 ms |
| worst heap change during processing | −44 B |
| lowest free heap | 328 kB |
| deepest stack use | 4,684 B |
| radio, receiving | 15.8 mA, 52.4 mW at 3.30 V |
| radio, standby | 2.2 mA |
| radio, 2 dBm transmit | 69.2 mA, 228 mW |
| radio, sleep | below the INA219's 0.1 mA resolution |

The power figures are the radio's own supply (the INA219 sits between the
regulator and the Ra-01); the ESP32, its regulator and the USB bridge are
not included.

## On your own bench

1. **Link test and calibration.** Flash `firmware/link_test`, then log both
   boards for two minutes and analyse:

   ```sh
   python3 benchlog.py --seconds 120 --out linktest.json
   python3 linktest_analysis.py linktest.json
   # optional: the ground station's view of the same frames
   journalctl -u cti-server --since "<start time>" -q > gs.log
   python3 linktest_analysis.py linktest.json --gs-log gs.log
   ```

   Add a steady mean error to `CALIB_HZ` (see [firmware.md](firmware.md#calibration)).

2. **Radio power.** With every transmitter silent, send `P` to the honeypot
   (three times for repeatability).

3. **Scenario run.** Flash `firmware/uplink_transmitter`. Erase the
   honeypot's store (`E`) and start the server with an empty database
   (`--reset`). Then:

   ```sh
   python3 benchlog.py --seconds 900 --out run.json --node-cmd R   # 15 min, resets the timing counters
   # silence the transmitter, send D to the honeypot, wait for "[dl] done"
   # copy ground_station/server/bench_cti.db from the Pi to ground.db
   python3 scenario_analysis.py run.json ground.db
   ```

   Send `S` to the honeypot after the run for the processing-time figures.

4. **Member mode.**

   ```sh
   python3 benchlog.py --seconds 360 --out member.json --node-cmd M
   python3 member_analysis.py member.json
   # send M again to return the node to honeypot mode
   ```

`benchlog.py` finds the Pico on `/dev/ttyACM*` and expects the honeypot on
`/dev/ttyUSB0`; use `--pico` and `--node` for other ports. Its output is
`{"pico": [[t, line], ...], "node": [[t, line], ...]}` with host timestamps;
the bundled logs use the key `esp` for the honeypot, which the scripts accept
as well.

## Synthetic evaluation

The detection pipeline was first checked on a labelled synthetic dataset
(150 uplink packets, 32 of them with injected anomalies):

```sh
cd simulation
pip install -r requirements.txt
python3 export.py
```

```
packets                : 150
malicious (ground truth): 32
detections             : 32  (TP=32 FP=0 FN=0 TN=118)
detection rate         : 1.000
false positive rate    : 0.000
```

The generator injects anomalies along the same features the detector scores,
so this confirms that the pipeline is internally consistent. It is not
evidence of performance against a real, adaptive attacker.
