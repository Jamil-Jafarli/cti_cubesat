# Radio link and data formats

## Radio channel

| Parameter | Value |
|---|---|
| Frequency | 433.5 MHz (ISM band) |
| Modulation | 2-FSK, no Gaussian shaping (RadioLib `beginFSK`) |
| Bit rate | 9.6 kb/s |
| Frequency deviation | 5 kHz |
| Receiver bandwidth | 58.6 kHz |
| AFC bandwidth | 83.3 kHz (receivers), started on the RSSI interrupt |
| Preamble | 64 bits |
| Sync word | RadioLib default |
| PHY CRC | on (CRC-16, checked in firmware, see below) |
| Output power | 2 dBm |
| Range on the bench | 1–2 m |

The flight concept uses the 435–438 MHz amateur-satellite band, which needs a
licence to transmit. The bench therefore runs in the ISM band at minimum power.
Every indicator is computed relative to the node's own centre frequency, so
the change of band does not affect the detection.

The receivers measure each frame's carrier offset from the SX1278's AFC
register (`RegAfcValue`, step 32 MHz / 2¹⁹ ≈ 61 Hz). RadioLib 7.7.1 does not
check the payload CRC in FSK mode, so the firmware reads the CRC-OK flag from
`RegIrqFlags2` before reading the FIFO and drops frames that fail it.

## AX.25 UI frame

Every frame on the air is an AX.25 UI frame inside one SX1278 packet:

```
┌─ SX1278 packet engine ────────────────────────────────────────────────────┐
│ preamble │ sync word │ length │           AX.25 UI frame           │ CRC  │
└──────────┴───────────┴────────┴────────────────────────────────────┴──────┘
                                   │
     ┌─────────────────────────────┘
     ▼
┌──────────────┬──────────────┬─────────┬──────┬─────────────┬────────┐
│ destination  │ source       │ control │ PID  │ info        │ FCS    │
│ 7 bytes      │ 7 bytes      │ 0x03    │ 0xF0 │ 0–46 bytes  │ 2 bytes│
└──────────────┴──────────────┴─────────┴──────┴─────────────┴────────┘
```

- **Addresses:** six callsign characters, each shifted left by one bit and
  padded with spaces, followed by an SSID byte (`0x60 | ssid << 1`; the last
  address sets bit 0). Callsigns carry no dash.
- **Control / PID:** `0x03` (UI frame, no connection) and `0xF0` (no layer 3).
- **FCS:** CRC-16/X.25 (polynomial 0x1021 reflected, init and xorout 0xFFFF),
  low byte first.

The AX.25 header is 18 bytes. The SX1278's FSK FIFO holds 64 bytes, so the
info field of a single frame is limited to 46 bytes.

The honeypot decodes frames even when the AX.25 FCS fails (the frame is then
recorded with `crc_ok = 0`, which the malformed-packet indicator uses); the
ground station rejects them.

## Frame types

| Direction | Source → destination | Info field |
|---|---|---|
| Uplink (scenario) | `GS100`…`GS109`, `UNK968`, `UNK971` → `HNY1` | `"<seq>|<command>"`, e.g. `"42|REBOOT"` |
| Uplink (link test) | `LNKTST` → `HNY1` | `"<seq>|O<offset>S<seq>"`, e.g. `"123|O+24S0123"` |
| Downlink | `HNY1` → `CTIGS` | one packed `RecordWire` (42 bytes) |

On the bench the commands are ASCII strings. A real mission would use binary
telecommands (for example CCSDS/PUS service numbers or CSP ports), and the
command classification would then need that mission's command dictionary.

## CTI record

The honeypot stores one fixed-size `Record` per frame in LittleFS
(`/records2.bin`, appended):

| Field | Type | Meaning |
|---|---|---|
| `t_ms` | uint32 | `millis()` at reception |
| `src` | char[10] | claimed source callsign |
| `cmd` | char[20] | command (info field after `|`) |
| `freq_dev_khz` | float | carrier offset, calibrated |
| `dop_hz` | float | Doppler residual from the onboard estimate |
| `rssi` | float | dBm |
| `crc_ok` | uint8 | AX.25 FCS valid |
| `gap_s` | float | seconds since the previous frame |
| `score` | uint8 | anomaly score 0–100 |
| `fuzzy` | float | best fuzzy-match score 0–1 |
| `cls` | char[12] | `known`, `suspicious` or `attacker` |
| `flagged` | uint8 | `score ≥ 50` |
| `conf` | float | confidence, `min(89.15, 42 + 0.53 × score)` |
| `fp` | char[21] | record identifier: first 10 bytes of SHA-256, hex |
| `sig` | char[18] | transmitter signature, e.g. `GS104@+0.0` |
| `wl` | uint8 | whitelist state: 0 none, 1 match, 2 mismatch |

## Downlink record (`RecordWire`)

A CSV record would be about 104 bytes, too long for one frame, so records
are downlinked packed (42 bytes, 60 bytes on the air with AX.25):

| Field | Type | Unit |
|---|---|---|
| `t_ms` | uint32 | ms |
| `src` | char[7] | callsign |
| `cmd` | char[20] | command |
| `dev_dahz` | int16 | carrier offset, 10 Hz |
| `res_dahz` | int16 | offset with the common-mode Doppler removed, 10 Hz |
| `dop_dahz` | int16 | Doppler residual, 10 Hz |
| `rssi_dbm` | int8 | dBm |
| `gap_ds` | uint8 | 0.1 s, saturating at 25.5 s |
| `fuzzy_x100` | uint8 | fuzzy score × 100 |
| `score` | uint8 | anomaly score |
| `flags` | uint8 | bit 0 `crc_ok`, bit 1 `flagged`, bits 2–3 whitelist state |

The class, confidence and signature are derived again on the ground, and the
SHA-256 identifier is not sent: the ground assigns its own.

The honeypot sends one record every 300 ms. The ground station re-arms AFC
and AGC after every frame and needs the gap to recover from a false start.

## Receiver output line

The CTI receiver expands every downlink record into one line on stdout, which
the server stores:

```
CTI,<t_ms>,<src>,<cmd>,<freq_dev_khz>,<dop_hz>,<rssi>,<crc_ok>,<gap_s>,<score>,<fuzzy>,<cls>,<flagged>,<conf>,<fp>,<sig>,<wl>
```

`fp` is empty in downlinked records; the server fills in its own identifier.
The server also accepts the 14-field form without `sig` and `wl`.
