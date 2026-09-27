# Analysis

| Script | Purpose |
|---|---|
| `benchlog.py` | logs the transmitter Pico and the honeypot side by side with host timestamps (needs pyserial) |
| `benchparse.py` | shared parsing and frame matching |
| `linktest_analysis.py` | link test: capture and carrier-offset error per offset; calibration |
| `scenario_analysis.py` | scenario run: capture, onboard and ground verdicts, carrier-offset error, alerts per scenario |
| `member_analysis.py` | member-mode run: verdicts per scenario |

```sh
python3 scenario_analysis.py ../data/2026-09-25-campaign/scenario_run.json ../data/2026-09-25-campaign/ground.db
```

The full procedure and the expected output are in
[docs/reproducing.md](../docs/reproducing.md).
