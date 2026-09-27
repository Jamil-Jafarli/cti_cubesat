# Bench campaign, 25 September 2026

Raw data of the measurement campaign reported in the documentation
([docs/reproducing.md](../../docs/reproducing.md)). Radio supply of the
honeypot: ESP32 3V3 → INA219 → Ra-01. Honeypot store and ground database
were empty at the start.

| File | Content |
|---|---|
| `scenario_run.json` | 15-minute run of `firmware/uplink_transmitter`: transmitter log (`pico`) and honeypot log (`esp`), host timestamps |
| `ground.db` | ground-station database after the downlink (148 of 148 records): tables `packets`, `alerts`, `indicator_state` |
| `honeypot_status.json` | the honeypot's status report (`S`) after the uplink: processing time, heap, stack, receiver counters |
| `power.json` | three runs of the honeypot's radio power profile (`P`) |
| `linktest_900ms.json` | `firmware/link_test` at 0.9 s frame spacing, transmitter and honeypot logs |
| `linktest_500ms.json` | the same at 0.5 s frame spacing |
| `member_run.json` | 6-minute run with the honeypot in member mode, after the bench had been disturbed |

The honeypot's serial log becomes unreliable after about 800 s of the scenario
run (USB passthrough), so capture is computed from the ground database, which
holds the honeypot's complete store.

```sh
cd analysis
python3 scenario_analysis.py ../data/2026-09-25-campaign/scenario_run.json ../data/2026-09-25-campaign/ground.db
```
