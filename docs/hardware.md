# Hardware

The bench has three nodes. All three radios are SX1278 transceivers on the
433 MHz ISM band, driven by the same library (RadioLib 7.7.1) and the same
framing code (`libraries/HnyProto`).

| Node | Role | Board | Radio |
|---|---|---|---|
| Uplink transmitter | plays five ground stations and an attacker | Raspberry Pi Pico | Dorji DRF1278F |
| Honeypot node | the CubeSat's detection board | ESP32-WROOM-32D development board | Ai-Thinker Ra-01 |
| CTI ground station | receives the downlink, runs the server and portal | Raspberry Pi 4 Model B | Ai-Thinker Ra-01 |

## Bill of materials

| Qty | Part | Notes |
|---|---|---|
| 1 | Raspberry Pi Pico | uplink transmitter (the same board runs the link test) |
| 1 | Dorji DRF1278F module (SX1278, 433 MHz) | castellated, 1.27 mm pitch |
| 1 | ESP32-WROOM-32D development board | 30- or 38-pin DevKit, "ESP32 Dev Module" in the Arduino IDE |
| 2 | Ai-Thinker Ra-01 module (SX1278, 433 MHz) | honeypot node and ground station, 1.27 mm pitch |
| 1 | INA219 current-monitor breakout, 0.1 Ω shunt | radio supply monitor on the honeypot node |
| 1 | Raspberry Pi 4 Model B, Raspberry Pi OS | ground station |
| 4 | 3 mm or 5 mm LEDs: red, amber, green, blue | verdict indicators |
| 4 | resistors: 220 Ω (red, green, blue), 100 Ω (amber) | LED series resistors |
| 3 | 100 nF ceramic capacitor | one per radio module |
| 3 | 10–47 µF electrolytic capacitor, ≥ 6.3 V | one per radio module |
| 3 | 17.3 cm straight wire (or a 433 MHz spring antenna) | quarter-wave antenna for each radio |
| – | perfboard, thin wire, headers, USB cables | |

The SX1278 modules are 3.3 V parts: never connect them to 5 V. Both module
types have 1.27 mm pads and do not fit a breadboard; solder thin wires to them
or use a breakout adapter.

## Wiring

Pins are given by name. On the Raspberry Pi 4 the physical header position is
added, because the header itself is not labelled.

### Uplink transmitter: DRF1278F → Raspberry Pi Pico

| DRF1278F | Pico |
|---|---|
| SCK | GP18 |
| MOSI | GP19 |
| MISO | GP20 |
| NSS | GP17 |
| RESET | GP22 |
| DIO0 | GP21 |
| VCC | 3V3(OUT) |
| GND (both) | GND |
| ANT | 17.3 cm wire |

MISO must be an SPI0 RX-capable pin (GP0, GP4, GP16 or GP20); change `PIN_MISO`
in the sketch if you use another one. DIO1–DIO5 stay unconnected.

![Uplink transmitter schematic](images/uplink_transmitter_schematic.png)

### Honeypot node: Ra-01, INA219 and LEDs → ESP32

| From | To (ESP32) |
|---|---|
| Ra-01 SCK | IO18 |
| Ra-01 MISO | IO19 |
| Ra-01 MOSI | IO23 |
| Ra-01 NSS | IO5 |
| Ra-01 RESET | IO14 |
| Ra-01 DIO0 | IO26 |
| Ra-01 3.3V | INA219 VIN− |
| INA219 VIN+ | 3V3 (a separate wire) |
| INA219 VCC | 3V3 |
| INA219 GND | GND |
| INA219 SDA | IO21 |
| INA219 SCL | IO22 |
| Ra-01 GND (all three) | GND |
| red LED anode, through 220 Ω | IO32 |
| amber LED anode, through 100 Ω | IO17 |
| green LED anode, through 220 Ω | IO16 |
| blue LED anode, through 220 Ω | IO4 |
| LED cathodes | GND |

The radio's supply runs ESP32 3V3 → INA219 VIN+ → shunt → VIN− → Ra-01 3.3V,
so the INA219 measures the radio's current and nothing else. The node works
without the INA219 if VIN+ and VIN− are bridged; only the `P` power profile is
then unavailable.

Keep IO0 (BOOT button), IO2, IO12, IO15 and IO6–IO11 free. IO16 and IO17 are
free on WROOM modules only; on a WROVER board move the green and amber LEDs
to other pins. IO25 is an optional COM_TX_ACTIVE input (active low, internal
pull-up) that parks the receiver while the satellite's own radio transmits;
leave it unconnected on the bench.

LED meanings:

| LED | Honeypot mode | Member mode |
|---|---|---|
| red | flagged or classified as attacker | blocked |
| amber | suspicious | allowlist override or spoof suspect |
| green | known ground station | accepted |
| blue | downlink in progress | downlink in progress |

The red, amber and green LEDs hold the last verdict until the next frame.

![Honeypot node schematic](images/honeypot_node_schematic.png)

### CTI ground station: Ra-01 → Raspberry Pi 4

| Ra-01 | Raspberry Pi 4 | Header pin |
|---|---|---|
| 3.3V | 3V3 | 17 |
| GND | GND | 20 |
| SCK | GPIO11 (SPI0 SCLK) | 23 |
| MISO | GPIO9 (SPI0 MISO) | 21 |
| MOSI | GPIO10 (SPI0 MOSI) | 19 |
| NSS | GPIO8 (SPI0 CE0) | 24 |
| RESET | GPIO25 | 22 |
| DIO0 | GPIO24 | 18 |
| ANT | 17.3 cm wire | – |

Header pin 1 is the corner farthest from the USB and Ethernet ports (square
solder pad); odd pins are on the inner row. Pins 2 and 4 carry 5 V; do not
connect the radio there. The kernel's SPI driver drives NSS (CE0), so SPI must
be enabled (`sudo raspi-config nonint do_spi 0`).

The schematic below takes 3V3 and GND from header pins 1 and 39; any 3V3 and
GND pin works.

![Ground station schematic](images/ground_station_schematic.png)

## Power and decoupling

Put a 100 nF ceramic and a 10–47 µF electrolytic capacitor across each radio
module's 3.3 V and GND, as close to the module as possible (positive lead of
the electrolytic to 3.3 V). On the bench, supply dips at the radio were enough
to reset the SX1278 without resetting the microcontroller; the firmware
detects this and reconfigures the radio, but good decoupling prevents it.

Power the radios from the boards' own 3.3 V regulators. On the honeypot node
a separate switching converter in the radio supply added noise next to the
receiver and a voltage drop on mode changes, and was removed.

## Antennas and placement

Each radio needs an antenna: a 17.3 cm straight wire soldered to ANT (a
quarter wave at 433 MHz) or a 433 MHz spring antenna. Never transmit without
an antenna. Keep the Ra-01 at least 3 cm from the ESP32 board's own PCB
antenna. The bench runs at 2 dBm over 1–2 m; the received level is typically
−40 to −60 dBm.

## Fritzing files

`hardware/fritzing/` holds the Fritzing sketches of the three nodes and a
Fritzing part for the Dorji DRF1278F, which is not in the standard library.
Import `parts/DRF1278F_Dorji_SX1278.fzpz` first (File → Open), then open the
sketches. The Ra-01, ESP32 DevKit, INA219 and Raspberry Pi Pico parts are
embedded in the sketches; they come from community part libraries.
