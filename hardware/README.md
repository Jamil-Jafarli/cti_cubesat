# Hardware files

| File | Content |
|---|---|
| `fritzing/uplink_transmitter.fzz` | Raspberry Pi Pico + DRF1278F |
| `fritzing/honeypot_node.fzz` | ESP32 DevKit + Ra-01 + INA219 + four LEDs |
| `fritzing/ground_station.fzz` | Raspberry Pi 4 + SX1278 radio (drawn with the DRF1278F symbol; the bench uses a Ra-01 with the same connections) |
| `fritzing/parts/DRF1278F_Dorji_SX1278.fzpz` | Fritzing part for the Dorji DRF1278F (17 × 17 mm, 15 castellated pads at 1.27 mm), made from the DRF1278F datasheet Rev 1.1 |

Open the part file in Fritzing first (File → Open), so that the sketches that
use it find it. The other parts are embedded in the sketches.

Wiring tables, the bill of materials and notes on power and antennas are in
[docs/hardware.md](../docs/hardware.md).
