# Firmware

| Sketch | Board | Role |
|---|---|---|
| [`honeypot_node`](honeypot_node/honeypot_node.ino) | ESP32 Dev Module | the honeypot's detection board: capture, score, fingerprint, store, downlink; member mode |
| [`uplink_transmitter`](uplink_transmitter/uplink_transmitter.ino) | Raspberry Pi Pico | uplink scenario: five ground stations and five attack types |
| [`link_test`](link_test/link_test.ino) | Raspberry Pi Pico | link measurement and calibration |

All sketches need RadioLib 7.7.1 and the shared library in
[`../libraries/HnyProto`](../libraries/HnyProto):

```sh
arduino-cli compile -b esp32:esp32:esp32     --library libraries/HnyProto firmware/honeypot_node
arduino-cli compile -b rp2040:rp2040:rpipico --library libraries/HnyProto firmware/uplink_transmitter
arduino-cli compile -b rp2040:rp2040:rpipico --library libraries/HnyProto firmware/link_test
```

Each sketch starts with a header that lists its wiring, build settings and
serial commands. Toolchain, configuration, serial output and calibration are
described in [docs/firmware.md](../docs/firmware.md).
