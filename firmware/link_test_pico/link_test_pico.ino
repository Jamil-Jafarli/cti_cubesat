/* ═══════════════════════════════════════════════════════════════════════
   Bench RF link test: Raspberry Pi Pico + SX1278 (same wiring as
   gs_uplink_pico). Not part of the attack scenario — it measures the link.

   The scenario sketch sends ~10 frames a minute, mixes carrier offsets,
   Doppler and attack types, and so cannot tell a lossy link from a lossy
   configuration. This one sends 2 frames a second, each carrying its own
   sequence number and carrier offset, so every receiver's log can be
   matched frame by frame and loss measured per offset:

       src LNKTST -> HNY1, info "<seq>|O<+off>S<seq>"   e.g. "123|O+24S0123"

   The honeypot prints the part after '|' as the command, the Pi ground
   station prints the info field, the sketch prints what it sent.

   Serial commands (one character):
     r  round-robin offsets 0, -8, +8, -4, +4, +24, +28 kHz (default)
     z  0 kHz only — no offset, so AFC has nothing to correct
     1..9  frame interval in hundreds of ms (default 5 = 500 ms)
   ═══════════════════════════════════════════════════════════════════════ */
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
  // identical radio parameters to gs_uplink_pico
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
