# CTI CubeSat bench — honeypot node, test transmitter and CTI ground station

A three-node bench that runs a honeypot-CubeSat threat-intelligence chain over a
real 433 MHz radio link:

```
 transmitter (Pico)          honeypot node (ESP32)             CTI ground station (Raspberry Pi 4)
 gs_uplink_pico      --RF--> hny_node_esp32            --RF--> gs_cti_pi  --stdout-->  hny_server.py
 5 ground stations +         listens, measures the carrier,    receives the downlink       SQLite + ground analysis
 scripted attacks            scores, fingerprints, stores      of stored records           + web portal (port 8700)
                             every frame; member mode gives
                             accept/block verdicts
```

- **Uplink:** the transmitter plays five legitimate ground stations (each with its own
  carrier offset, applying a simulated pass Doppler) and injects attacks: an off-frequency
  unregistered source, a probing burst, a callsign spoof, a Doppler spoof and a frame with a
  corrupted AX.25 FCS.
- **Honeypot node:** measures each frame's carrier offset with the SX1278's AFC, scores it
  with seven indicators, fingerprints it, checks an RF-signature whitelist, and stores a
  record in flash. In member mode it answers accept/block from a blocklist instead.
- **Downlink:** on command the node sends its stored records as AX.25 frames to the ground
  station, which re-scores them, fits the pass Doppler, raises alerts, builds attacker
  profiles and serves the portal (with STIX 2.1 / MISP / CSV export).

The bench is a research prototype. Everything runs in the 433.05–434.79 MHz ISM band at
2 dBm over 1–2 m; check your local radio regulations before transmitting.

## Repository layout

```
libraries/HnyProto/        shared header: AX.25 framing, record format, detection math
firmware/
  hny_node_esp32/          honeypot node (ESP32 + Ra-01 + INA219 + LEDs)
  gs_uplink_pico/          scenario transmitter (Raspberry Pi Pico + DRF1278F)
  link_test_pico/          link test transmitter: sequence-numbered frames, 7 offsets
ground_station/
  gs_cti_pi/               downlink receiver for the Raspberry Pi (C++, RadioLib + lgpio)
  server/                  hny_server.py, cti_engine.py, web portal, systemd unit
platform/                  synthetic-data detection pipeline (generator, detector, dashboard)
analysis/                  bench logging and the scripts that produce the measured results
figures/                   figures (wiring diagrams and photos go in wiring/ and photos/)
```

## Hardware

| Node | Parts |
|---|---|
| Honeypot | ESP32-WROOM-32D dev board, Ai-Thinker Ra-01 (SX1278), INA219 module (0.1 Ω shunt), 4 LEDs + resistors (red 300 Ω, amber 200 Ω, green 100–300 Ω, blue 200 Ω), 10 µF + 100 nF |
| Transmitter | Raspberry Pi Pico, Dorji DRF1278F (SX1278), 10 µF + 100 nF |
| Ground station | Raspberry Pi 4 (Raspberry Pi OS), Ai-Thinker Ra-01 (SX1278), 10 µF + 100 nF |
| Each radio | a 17.3 cm straight wire antenna (λ/4 at 433 MHz) |

Put the 10 µF + 100 nF across each radio module's 3.3 V and GND pins, at the module, with
the capacitor's ground going to the module's own GND pad. The radio modules are 3.3 V
only.

## Wiring

### Honeypot node — Ra-01, INA219 and LEDs to the ESP32

| From | To (ESP32) |
|---|---|
| Ra-01 SCK / MISO / MOSI / NSS | IO18 / IO19 / IO23 / IO5 |
| Ra-01 RESET / DIO0 | IO14 / IO26 |
| Ra-01 3.3V | INA219 VIN− |
| INA219 VIN+ | 3V3 (separate wire) |
| INA219 VCC / GND | 3V3 / GND |
| INA219 SDA / SCL | IO21 / IO22 |
| Ra-01 GND (all three) | GND |
| LED red / amber / green / blue (anode, via resistor) | IO32 / IO17 / IO16 / IO4 |
| LED cathodes | GND |

The radio's supply runs `ESP32 3V3 → INA219 VIN+ → shunt → VIN− → Ra-01 3.3V`, so the
INA219 measures the radio's current and nothing else. Leave IO0 (BOOT button), IO2, IO12,
IO15 and IO6–IO11 free. IO25 is an optional "main radio transmitting" input (active low,
internal pull-up) that parks the receiver.

### Transmitter — DRF1278F to the Raspberry Pi Pico

| DRF1278F | Pico |
|---|---|
| SCK / MOSI / MISO / NSS | GP18 / GP19 / GP20 / GP17 |
| RESET / DIO0 | GP22 / GP21 |
| VCC / GND | 3V3(OUT) / GND |

MISO must be on an SPI0 RX-capable pin (GP0, GP4, GP16 or GP20).

### Ground station — Ra-01 to the Raspberry Pi 4 header

| Ra-01 | Pi 4 | Header pin |
|---|---|---|
| 3.3V | 3V3 | 17 |
| GND | GND | 20 |
| SCK | GPIO11 (SPI0 SCLK) | 23 |
| MISO | GPIO9 (SPI0 MISO) | 21 |
| MOSI | GPIO10 (SPI0 MOSI) | 19 |
| NSS | GPIO8 (SPI0 CE0) | 24 |
| RESET | GPIO25 | 22 |
| DIO0 | GPIO24 | 18 |

Header pin 1 is at the end farthest from the USB/Ethernet ports. Pins 2 and 4 are 5 V — do
not connect the radio there.

## Building and flashing the microcontrollers

Tested with Arduino CLI, **RadioLib 7.7.1**, esp32 core **2.0.17** and arduino-pico
(rp2040) core **6.1.0**.

```
arduino-cli lib install RadioLib@7.7.1
arduino-cli core install esp32:esp32@2.0.17
arduino-cli core install rp2040:rp2040          # board index: arduino-pico (earlephilhower)

# honeypot node (default partition scheme keeps a LittleFS area for the records)
arduino-cli compile -b esp32:esp32:esp32 --library libraries/HnyProto firmware/hny_node_esp32
arduino-cli upload  -b esp32:esp32:esp32:UploadSpeed=115200 -p /dev/ttyUSB0 firmware/hny_node_esp32

# scenario transmitter (or firmware/link_test_pico for link tests)
arduino-cli compile -b rp2040:rp2040:rpipico --library libraries/HnyProto firmware/gs_uplink_pico
arduino-cli upload  -b rp2040:rp2040:rpipico -p /dev/ttyACM0 firmware/gs_uplink_pico
```

With the Arduino IDE instead: copy `libraries/HnyProto` into your Arduino `libraries`
folder, install RadioLib 7.7.1, and pick *ESP32 Dev Module* / *Raspberry Pi Pico*.

## Setting up the ground station (Raspberry Pi 4)

```
sudo apt install cmake g++ liblgpio-dev python3
sudo raspi-config nonint do_spi 0           # /dev/spidev0.0 must appear
git clone https://github.com/Jamil-Jafarli/cti_cubesat.git ~/cti-cubesat-bench
cd ~/cti-cubesat-bench/ground_station/gs_cti_pi && ./build.sh     # fetches RadioLib 7.7.1
cd ../server && python3 hny_server.py --radio --host 0.0.0.0
# portal: http://<pi-address>:8700
```

To start it at boot, edit `User`, `Group` and `WorkingDirectory` in
`ground_station/server/cti-server.service`, then:

```
sudo cp ground_station/server/cti-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now cti-server
journalctl -u cti-server -f
```

The receiver measures the noise floor at start and sets its trigger threshold 15 dB above
it (`--rssi-threshold` overrides it). Without hardware, `python3 hny_server.py --simulate`
drives the portal from the synthetic pipeline (install `platform/requirements.txt`).

## Running a session

1. Flash the three boards, power them up 1–2 m apart. On the honeypot's serial console
   (115200 baud) the boot lines report the INA219, the noise floor and the trigger threshold.
2. Let the transmitter run: each captured frame prints an `[rx]` line with the measured
   offset, score, class and whitelist verdict, and the LEDs show the last verdict.
3. Stop the transmitter (unplug it) and type `D` on the honeypot: the stored records are
   downlinked and appear in the portal.

Honeypot serial commands:

| Key | Action |
|---|---|
| `S` | status JSON: stored records, receive counters, timing, heap, stack, radio state |
| `D` | downlink every stored record to the ground station (BOOT button does the same) |
| `E` | erase the record store |
| `R` | reset the timing counters |
| `M` | toggle honeypot / member mode |
| `F` / `A` / `X` | show whitelist / enrol the last source / clear the whitelist |
| `P` | radio power profile via the INA219 (listening, standby, sleep, 2 dBm carrier) |
| `Q` | in-band RSSI scan, 433.40–433.60 MHz (run it with every transmitter silent) |

## Calibration

The two radios' crystals differ by a few kHz, and the difference changes whenever a module
is replaced or reworked. Flash `firmware/link_test_pico`, log a minute or two with
`analysis/benchlog.py`, and run `analysis/linktest_analysis.py`: it prints the mean
carrier-offset error of the honeypot, which you add (in Hz) to `CALIB_HZ` in
`firmware/hny_node_esp32/hny_node_esp32.ino`. A calibrated node reads Doppler-free
frames to within ±0.4 kHz.

## Reproducing the measurements

See [`analysis/README.md`](analysis/README.md): link test, power profile, the 15-minute
end-to-end scenario run with downlink and ground analysis, and the member-mode run.

## Known limitations

- **Throughput.** The honeypot scores, fingerprints and writes every frame to flash before
  it listens again. It keeps up with frames ~0.9 s apart (97 % in the link test) but loses
  most frames sent every 0.5 s (9 %), while the ground station decodes both. Batching the
  flash writes off the receive path is the obvious fix and is not implemented.
- **Modulation.** The link is plain 2-FSK (RadioLib's `beginFSK` disables Gaussian shaping);
  the modulation indicator cannot fire on an SX127x packet receiver.
- **Doppler on the board** is estimated from the cooperative stations (running median), not
  from an orbit model; it lags the fastest part of a pass and can misreport the whitelist
  near closest approach.
- **Member mode** uses a blocklist and allowlist compiled into `HnyProto.h`; distributing
  the ground-built blocklist to member nodes over RF is not implemented.
- The RSSI trigger, the receive watchdogs and the radio health check are tuned for this
  bench; see the comments in `hny_node_esp32.ino` and `gs_cti_pi.cpp` for why each exists.
