# Ground station

Runs on a Raspberry Pi 4 with a Ra-01 on SPI0.

| Folder | Content |
|---|---|
| [`receiver`](receiver) | `cti_receiver` (C++, RadioLib + lgpio): receives the honeypot's downlink and prints one `CTI,<csv>` line per record |
| [`server`](server) | `hny_server.py`: stores the records (SQLite), runs the ground analysis and serves the portal on port 8700; `cti_engine.py`: detection rules, profiles, indicators and STIX/MISP/CSV export; `web/`: the portal; `cti-server.service`: systemd unit |

```sh
sudo apt install cmake g++ liblgpio-dev python3
sudo raspi-config nonint do_spi 0
receiver/build.sh
cd server && python3 hny_server.py --radio --host 0.0.0.0
```

Without hardware: `python3 hny_server.py --simulate --reset` (needs
`simulation/requirements.txt`). Setup, options, the portal, the HTTP API and
troubleshooting are described in [docs/ground-station.md](../docs/ground-station.md).
