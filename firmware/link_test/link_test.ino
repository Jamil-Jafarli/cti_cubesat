/* ═══════════════════════════════════════════════════════════════════════════
   Link test — Raspberry Pi Pico + SX1278 (same hardware and wiring as
   firmware/uplink_transmitter)

   Measures the RF link rather than the detection. The scenario sketch sends
   a few frames a minute with mixed offsets, Doppler and attacks, so it cannot
   tell a lossy link from a lossy configuration. This sketch sends frames at a
   fixed interval, each carrying its own sequence number and carrier offset,
   so every receiver's log can be matched frame by frame and loss and offset
   error measured per offset:

       LNKTST -> HNY1, info "<seq>|O<offset>S<seq>"     e.g. "123|O+24S0123"

   The honeypot prints the part after '|' as the command, the ground station
   prints the whole info field, and this sketch prints what it sent. The
   Doppler-free frames are also what the honeypot's CALIB_HZ is measured on
   (analysis/linktest_analysis.py).

   Wiring
     DRF1278F  SCK  -> GP18    MOSI -> GP19    MISO -> GP20    NSS -> GP17
               RESET -> GP22   DIO0 -> GP21    VCC  -> 3V3(OUT)  GND -> GND

   Serial commands (115200 baud, one character)
     r      round-robin offsets 0, -8, +8, -4, +4, +24, +28 kHz (default)
     z      0 kHz only
     1..9   frame interval in hundreds of milliseconds (default 5 = 500 ms)

   Output: one "[lt] seq=... off=... sent" line per frame.
   ═══════════════════════════════════════════════════════════════════════════ */
#include <RadioLib.h>
#include <HnyProto.h>

#define PIN_SCK 18
#define PIN_MOSI 19
#define PIN_MISO 20
#define PIN_NSS 17
#define PIN_RST 22
#define PIN_DIO0 21
SX1278 radio = new Module(PIN_NSS, PIN_DIO0, PIN_RST, RADIOLIB_NC);

static const float CENTER_MHZ = 433.5f;
static const int OFFSETS_KHZ[] = {0, -8, 8, -4, 4, 24, 28};
static const size_t N_OFF = sizeof(OFFSETS_KHZ) / sizeof(OFFSETS_KHZ[0]);

static bool zeroOnly = false;
static uint32_t intervalMs = 500;
static uint32_t seq = 0;

void setup() {
  Serial.begin(115200);
  delay(1500);
  pinMode(LED_BUILTIN, OUTPUT);
  SPI.setSCK(PIN_SCK); SPI.setTX(PIN_MOSI); SPI.setRX(PIN_MISO); SPI.begin();
  Serial.print("[lt] SX1278 init ... ");
  // same radio parameters as the uplink transmitter
  int st = radio.beginFSK(CENTER_MHZ, 9.6, 5.0, 58.6, 2, 64);
  if (st != RADIOLIB_ERR_NONE) { Serial.printf("FAIL %d\n", st); while (1) delay(1000); }
  radio.setCRC(true);
  Serial.println("ok — link test, 'r' round-robin, 'z' 0 kHz only, '1'..'9' interval");
}

void loop() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == 'r') { zeroOnly = false; Serial.println("[lt] mode: round-robin offsets"); }
    else if (c == 'z') { zeroOnly = true; Serial.println("[lt] mode: 0 kHz only"); }
    else if (c >= '1' && c <= '9') {
      intervalMs = (uint32_t)(c - '0') * 100;
      Serial.printf("[lt] interval %lu ms\n", (unsigned long)intervalMs);
    }
  }

  int off = zeroOnly ? 0 : OFFSETS_KHZ[seq % N_OFF];
  radio.setFrequency(CENTER_MHZ + off / 1000.0f);
  char info[40];
  int ilen = snprintf(info, sizeof(info), "%lu|O%+03dS%04lu",
                      (unsigned long)seq, off, (unsigned long)(seq % 10000));
  uint8_t frame[64];
  size_t n = ax25_build(frame, sizeof(frame), "HNY1", 0, "LNKTST", 0,
                        (uint8_t *)info, ilen);
  uint32_t t0 = millis();
  int st = radio.transmit(frame, n);
  digitalWrite(LED_BUILTIN, HIGH); delay(20); digitalWrite(LED_BUILTIN, LOW);
  Serial.printf("[lt] seq=%lu off=%+d len=%u %s\n", (unsigned long)seq, off,
                (unsigned)n, st == RADIOLIB_ERR_NONE ? "sent" : "ERR");
  seq++;
  uint32_t spent = millis() - t0;
  delay(spent < intervalMs ? intervalMs - spent : 0);
}
