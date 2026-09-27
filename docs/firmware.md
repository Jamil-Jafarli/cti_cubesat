# Firmware

| Sketch | Board | Purpose |
|---|---|---|
| `firmware/honeypot_node` | ESP32 Dev Module | honeypot detection board: capture, score, store, downlink; member mode |
| `firmware/uplink_transmitter` | Raspberry Pi Pico | uplink scenario: five ground stations and five attack types |
| `firmware/link_test` | Raspberry Pi Pico | link measurement: numbered frames at fixed offsets and intervals |

All three use RadioLib and the shared header-only library
`libraries/HnyProto`.

## Toolchain

Tested with:

| Component | Version |
|---|---|
| Arduino CLI / Arduino IDE 2 | any recent |
| esp32 core (Espressif) | 2.0.17 |
| rp2040 core (Earle Philhower, arduino-pico) | 6.1.0 |
| RadioLib | 7.7.1 |

The esp32 3.x core has not been tested.

## Build and upload with arduino-cli

```sh
arduino-cli config add board_manager.additional_urls \
  https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json
arduino-cli core update-index
arduino-cli core install esp32:esp32@2.0.17 rp2040:rp2040@6.1.0
arduino-cli lib install RadioLib@7.7.1

# honeypot node (ESP32)
arduino-cli compile -b esp32:esp32:esp32 --library libraries/HnyProto firmware/honeypot_node
arduino-cli upload  -b esp32:esp32:esp32 -p /dev/ttyUSB0 firmware/honeypot_node

# uplink transmitter (Pico); use firmware/link_test for link measurements
arduino-cli compile -b rp2040:rp2040:rpipico --library libraries/HnyProto firmware/uplink_transmitter
arduino-cli upload  -b rp2040:rp2040:rpipico -p /dev/ttyACM0 firmware/uplink_transmitter
```

If the ESP32 upload fails at the default speed (for example through a
virtual machine's USB passthrough), add `:UploadSpeed=115200` to the board
name. A Pico that does not show a serial port can be put into its bootloader
by holding BOOTSEL while plugging it in; it then mounts as a drive and takes
the `.uf2` file from the build folder.

With the Arduino IDE, copy `libraries/HnyProto` into your sketchbook's
`libraries` folder, install RadioLib 7.7.1 from the Library Manager and select
"ESP32 Dev Module" or "Raspberry Pi Pico". The honeypot needs a partition
scheme with a SPIFFS/LittleFS area (the default one has it).

## Honeypot node

### Configuration

The constants at the top of `honeypot_node.ino`:

| Constant | Default | Meaning |
|---|---|---|
| `CENTER_MHZ` | 433.5 | channel centre |
| `CALIB_HZ` | 2730 | crystal offset between this receiver and the transmitter; see calibration |
| `FLOOR_MARGIN_DB` | 15 | RSSI trigger at least this far above the noise floor |
| `FRAME_MARGIN_DB` | 30 | RSSI trigger follows the received frames at this distance below them |
| `FP_MAX` | 8 | whitelist entries |
| `FP_ENROL_TOL_KHZ` | 1.5 | whitelist tolerance on the residual |
| `DOP_WIN`, `DOP_MIN_N` | 8, 3 | Doppler estimator window and minimum samples |
| `PIN_…` | see the header | wiring |

The detection constants (weights, thresholds, registry, allowlist and
blocklist) are in `libraries/HnyProto/HnyProto.h`.

### Serial commands

Open the serial monitor at 115200 baud and send one character:

| Key | Action |
|---|---|
| `D` | downlink every stored record to the ground station (the BOOT button does the same) |
| `S` | status JSON |
| `E` | erase the record store |
| `R` | reset the timing counters |
| `M` | toggle honeypot / member mode |
| `F` | print the fingerprint whitelist |
| `A` | enrol the transmitter of the last received frame |
| `X` | clear the whitelist (fail-open until re-enrolled) |
| `P` | radio power profile: receive, standby, sleep and a 2 dBm carrier |
| `Q` | RSSI scan of 433.40–433.60 MHz in 2 kHz steps (all transmitters off) |

### Output

At boot the node reports the INA219, the measured noise floor and the RSSI
trigger level, then one line per event:

```
[rx] GS104  PING                 dev=  +5.9 res=  -0.2 dop=  -216Hz rssi=-50 score= 0 known      WL-OK
[rx] UNK971 0x7F_UNKNOWN_OPCODE  dev= +23.8 res= +17.8 dop=+17775Hz rssi=-51 score=70 attacker   FLAG
[rx] GS102  HK_DUMP              dev=  +1.9 res=  -4.0 dop=   -28Hz rssi=-50 score=10 known      BAD-FCS
[mbr] GS104  ERASE_FLASH          dev=  +0.1kHz wl=MISMATCH -> BLOCK  (blocklist)
[dl] done: 148/148 sent
```

(taken from the 2026-09-25 campaign logs in `data/`)

`dev` is the calibrated carrier offset in kHz, `res` the offset with the
onboard Doppler estimate removed, `dop` the Doppler residual. `BAD-FCS`,
`FLAG`, `WL-OK` and `WL-MISMATCH` mark the malformed-packet indicator, a
flagged frame and the whitelist state.

The status JSON (`S`):

| Field | Meaning |
|---|---|
| `stored` | records in flash |
| `fs_used`, `fs_total` | LittleFS usage, bytes |
| `wl_entries` | whitelist entries |
| `rx_raw` | every RxDone, decodable or not |
| `crc_bad` | frames dropped for a failed PHY CRC |
| `rx_stuck` | receiver restarts after a sync match that never completed |
| `radio_reinit` | times the radio was found at its reset defaults and reconfigured |
| `rx_mode_fix` | times the radio was found in standby or sleep |
| `rx_polled` | frames served from the PayloadReady flag (missed DIO0 edge) |
| `opmode`, `irq` | raw `RegOpMode` and IRQ flags |
| `rssi_floor`, `rssi_trig`, `frame_rssi` | noise floor, current trigger, average frame RSSI (dBm) |
| `blank_n`, `blank_ms` | COM_TX_ACTIVE blanking windows and total time |
| `perf_n` | frames measured since the last `R` |
| `score_avg_us`, `score_max_us` | scoring and fingerprint time per frame |
| `store_avg_us`, `store_max_us` | flash write time per frame |
| `heap_delta_min`, `heap_free`, `heap_min_free` | heap behaviour, bytes |
| `stack_hwm` | deepest stack use of the loop task, bytes |

The power profile (`P`) prints `{"evt":"power",...}` with current (mA),
voltage (V) and power (mW) of the radio for each state. The INA219 resolves
0.1 mA, so the SX1278's sleep current reads as zero.

### Calibration

The two radios' crystals differ by a few kHz, and every carrier measurement
carries that difference. It depends on the module pair and changes when a
module is replaced or resoldered, so measure it on your own bench:

1. Flash `firmware/link_test` to the Pico; let it send for one to two minutes
   (send `z` for 0 kHz only, or keep the default round-robin of offsets).
2. Log both boards: `python3 analysis/benchlog.py --seconds 120 --out linktest.json`.
3. Run `python3 analysis/linktest_analysis.py linktest.json`. It prints the
   honeypot's mean carrier-offset error.
4. Add that error (in Hz) to `CALIB_HZ` and reflash the honeypot.

A calibrated node reads Doppler-free frames to within ±0.4 kHz.

### Receiver robustness

The receiver configuration and the watchdogs in the sketch each address a
failure seen on the bench; the comments next to the code explain them:

- AFC is required: without it the demodulator only locks on carriers within
  one deviation (5 kHz) of the tuned frequency and silently loses every
  transmitter further out. Raising the deviation instead makes the frequency
  measurement useless.
- The RSSI trigger must be above the noise floor (RadioLib's default of
  −127.5 dBm fires on noise and retunes AFC to nothing).
- The RSSI flag is sticky, so the false-start watchdog uses a window longer
  than one frame (60 ms).
- A supply dip can reset the SX1278 but not the ESP32; `radio_health()`
  checks a configured register once a second and reconfigures the radio.
- Frequency-synthesis RX (`RegOpMode` 0x0C) is the normal idle state of a
  receiver triggered on RSSI, not a fault.
- RadioLib does not check the payload CRC in FSK mode; the firmware reads the
  CRC-OK flag itself.

Porting the method to another SX127x-based receiver means repeating these
checks on that hardware.

## Uplink transmitter

Plays five legitimate stations (`GS100`, `GS102`, `GS104`, `GS107`, `GS109`
at −8, −4, 0, +4 and +8 kHz), each pre-compensating a simulated 10-minute pass
(±6 kHz peak Doppler), and after each of them one attack frame from a
rotating list:

| Attack | Source | Command | Carrier | Tests |
|---|---|---|---|---|
| combined attack | `UNK968` | `REBOOT` | +28 kHz, fixed | frequency, unknown source, command |
| impersonation | `GS104` | `ERASE_FLASH` | 0 kHz, fixed | whitelist, callsign spoof, destructive command |
| probing burst | `UNK971` | `0x7F_UNKNOWN_OPCODE` | +24 kHz, 0.9 s after the previous frame | probing, unknown opcode |
| Doppler spoof | `GS107` | `EPS_STATUS` | +4 kHz, fixed | Doppler mismatch only |
| malformed frame | `GS102` | `HK_DUMP` | −4 kHz, tracking | malformed packet only (AX.25 FCS broken) |

Each frame is logged as one line on USB serial:

```
[up] t= 24.3s GS104  -> HNY1  PING                 foff= +0.0 kHz  dop= +5965 Hz  legit            sent
[up] t= 29.3s UNK971 -> HNY1  0x7F_UNKNOWN_OPCODE  foff=+24.0 kHz  dop=    +0 Hz  probing burst    sent
```

## Link test

Sends `LNKTST` frames with a sequence number at a fixed interval, cycling the
carrier offset through 0, −8, +8, −4, +4, +24 and +28 kHz. Serial commands:
`r` round-robin offsets (default), `z` 0 kHz only, `1`–`9` interval in
hundreds of milliseconds (default 500 ms). Each frame is logged as one
`[lt] ...` line.
