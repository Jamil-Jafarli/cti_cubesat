/* ═══════════════════════════════════════════════════════════════════════════
   Honeypot node — ESP32 + SX1278 (Ai-Thinker Ra-01)

   The bench stand-in for the honeypot CubeSat's detection board. It listens
   to the uplink, and for every AX.25 frame it receives it:

     1. measures the RF metadata (carrier offset from the SX1278 AFC, RSSI,
        time since the previous frame),
     2. scores the frame with the seven-indicator anomaly score and the fuzzy
        transmitter match (HnyProto.h, the same math as simulation/detector.py),
     3. checks the transmitter against the fingerprint whitelist,
     4. appends a fixed-size CTI record to on-board flash (LittleFS).

   On command it downlinks every stored record to the CTI ground station as
   AX.25 UI frames HNY1 -> CTIGS. In member mode the board acts instead as the
   accept/block gate a member satellite would run: it prints a verdict and
   stores nothing.

   Hardware
     ESP32-WROOM-32D development board ("ESP32 Dev Module")
     Ai-Thinker Ra-01 (SX1278) receiver, powered through an INA219 shunt
     INA219 current monitor on the radio's 3.3 V line
     four verdict LEDs

   Wiring
     Ra-01  SCK  -> IO18    MISO -> IO19    MOSI -> IO23    NSS  -> IO5
            RESET -> IO14   DIO0 -> IO26    GND  -> GND
            3.3V -> INA219 VIN-   (INA219 VIN+ -> ESP32 3V3)
     INA219 VCC -> 3V3      GND -> GND      SDA -> IO21     SCL -> IO22
     LEDs   red IO32 (300 R), amber IO17 (200 R), green IO16 (300 R),
            blue IO4 (200 R); cathodes to GND
     IO0    BOOT button: starts a downlink
     IO25   optional COM_TX_ACTIVE input, active low (internal pull-up)

   Build
     Board "ESP32 Dev Module" (esp32 core 2.0.17), a partition scheme with a
     SPIFFS/LittleFS area, libraries RadioLib 7.7.1 and HnyProto.

   Serial commands (115200 baud, one character)
     D  downlink all stored records (the BOOT button does the same)
     S  status JSON: store, receiver counters, timing, heap and stack
     E  erase the record store
     R  reset the timing counters
     M  toggle honeypot / member mode
     F  print the fingerprint whitelist
     A  enrol the transmitter of the last received frame
     X  clear the whitelist
     P  radio power profile via the INA219
     Q  in-band RSSI scan, 433.40-433.60 MHz (run with all transmitters off)

   Output lines
     [rx]  one scored frame (honeypot mode)      [mbr] one verdict (member mode)
     [dl]  downlink progress                     [wl]  whitelist
     [hny] node events                           [scan] band scan
     {"evt":"status",...}, {"evt":"power",...}   machine-readable reports
   ═══════════════════════════════════════════════════════════════════════════ */
#include <RadioLib.h>
#include <LittleFS.h>
#include <mbedtls/sha256.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <HnyProto.h>
#include <Wire.h>
#include <algorithm>

/* ── pins ─────────────────────────────────────────────────────────────── */
#define PIN_SCK 18
#define PIN_MISO 19
#define PIN_MOSI 23
#define PIN_NSS 5
#define PIN_RST 14
#define PIN_DIO0 26
#define PIN_LED 32             // red   — flagged or attacker
#define PIN_LED_G 16           // green — known ground station
#define PIN_LED_Y 17           // amber — suspicious
#define PIN_LED_B 4            // blue  — downlink in progress
#define PIN_BOOT 0
#define PIN_SDA 21             // INA219
#define PIN_SCL 22

/* COM_TX_ACTIVE: the satellite's main radio asserts this line while it
   transmits. That transmitter sits centimetres away in the same band at watt
   level, far above this receiver's maximum input, so the receiver is parked
   for the whole transmission. Active low with the internal pull-up: an
   unconnected pin reads "not transmitting". Flip TX_ACTIVE_LEVEL for a radio
   that drives the line high.                                                */
#define PIN_TX_ACTIVE 25
#define TX_ACTIVE_LEVEL LOW

/* ── radio ────────────────────────────────────────────────────────────── */
static Module *radioMod = new Module(PIN_NSS, PIN_DIO0, PIN_RST, RADIOLIB_NC);
SX1278 radio = radioMod;       // radioMod is kept for raw register access

static const float CENTER_MHZ = 433.5f;

/* Crystal offset between this receiver and the transmitter, subtracted from
   every carrier measurement. Measured with firmware/link_test on Doppler-free
   frames (analysis/linktest_analysis.py). It is a property of the module
   pair, not of the design: re-measure whenever a radio module is replaced or
   reworked.                                                                  */
static const float CALIB_HZ   = 2730.0f;

/* RSSI level that starts each AFC/AGC cycle. It must sit above the noise
   floor, or noise keeps restarting AFC, and not too far below the frames, or
   AGC is set on the transmitter's power ramp instead of the settled carrier.
   It starts at floor + FLOOR_MARGIN_DB (floor measured at boot) and then
   follows the received frames at their average RSSI - FRAME_MARGIN_DB,
   never below the floor limit.                                               */
static const float FLOOR_MARGIN_DB = 15.0f;
static const float FRAME_MARGIN_DB = 30.0f;
static float rssiTrigDbm = -75.0f;      // replaced at boot, then tracks the frames
static float rssiFloorDbm = NAN;
static float frameRssiAvg = NAN;        // exponential average of received frames

/* ── storage ──────────────────────────────────────────────────────────── */
// The store is versioned by file name: a file written with an older Record
// layout has a different stride, so it is deleted at boot instead of read.
static const char *STORE = "/records2.bin";
static const char *STORE_LEGACY = "/records.bin";
static const char *FP_STORE = "/fpallow.csv";

/* ── fingerprint whitelist ────────────────────────────────────────────── */
#define FP_MAX 8
static FpAllow fpAllow[FP_MAX];
static size_t  nFpAllow = 0;
static const float FP_ENROL_TOL_KHZ = 1.5f;   // temperature and ageing margin,
                                              // applied to the Doppler-free residual

// the last frame heard, so that 'A' can enrol its transmitter
static char  lastSrc[10] = {0};
static float lastDevKhz   = 0.0f;
static float lastResidKhz = 0.0f;
static bool  haveLastPkt = false;

/* ── common-mode Doppler estimate ─────────────────────────────────────── */
#define DOP_WIN 8
#define DOP_MIN_N 3
static float    dopWin[DOP_WIN];
static uint8_t  dopN = 0, dopI = 0;
static float    dopEstKhz = 0.0f;

/* ── board mode ───────────────────────────────────────────────────────── */
/* HONEYPOT scores, stores and later downlinks every frame. MEMBER is the
   gate a member satellite runs: it answers with an accept/block verdict from
   the CTI lists and stores nothing.                                         */
enum Mode : uint8_t { MODE_HONEYPOT = 0, MODE_MEMBER = 1 };
static Mode mode = MODE_HONEYPOT;

static const char *mode_name() {
  return mode == MODE_MEMBER ? "member" : "honeypot";
}

/* ── receiver state and counters (reported by 'S') ────────────────────── */
volatile bool rxFlag = false;
static uint32_t rxRaw = 0;       // every RxDone, decodable or not
static uint32_t rxStuck = 0;     // receiver restarts after a sync match that never completed
static uint32_t radioReinit = 0; // radio found at its reset defaults and reconfigured
static uint32_t rxModeFix = 0;   // radio found in standby or sleep, receiver restarted
static uint32_t rxCrcBad = 0;    // frames that failed the PHY CRC, dropped
static uint32_t rxPolled = 0;    // frames found by polling PayloadReady (no DIO0 edge)
void IRAM_ATTR onRx() { rxFlag = true; }
static uint32_t lastRxMs = 0;
static bool haveLast = false;
static uint32_t nStored = 0;
static bool     rxBlanked   = false;   // receiver parked while COM transmits
static uint32_t blankT0Ms   = 0;       // start of the current blanking window
static uint32_t blankN      = 0;       // blanking windows since boot
static uint32_t blankMsTotal = 0;      // total blanked time

/* Processing-time instrumentation. Scoring and the flash write are timed
   separately: the LittleFS write is one to two orders of magnitude slower
   and depends on the state of the flash, not on the algorithm.             */
struct Perf {
  uint32_t n;                            // frames measured
  uint32_t score_sum_us, score_max_us;   // hny_score() + fingerprint()
  uint32_t store_sum_us, store_max_us;   // store_record(), flash
  int32_t  heap_delta_min;               // most negative free-heap change seen
};
static Perf perf = {0, 0, 0, 0, 0, 0};

static inline void perf_add(uint32_t score_us, uint32_t store_us, int32_t heap_delta) {
  perf.n++;
  perf.score_sum_us += score_us;
  perf.store_sum_us += store_us;
  if (score_us > perf.score_max_us) perf.score_max_us = score_us;
  if (store_us > perf.store_max_us) perf.store_max_us = store_us;
  if (heap_delta < perf.heap_delta_min) perf.heap_delta_min = heap_delta;
}

/* ═══════════════════════════ radio configuration ═════════════════════════ */

/* Full receiver configuration. Applied at boot and again whenever the radio
   is found back at its reset defaults (radio_health()).                    */
static int radio_config() {
  // 2-FSK, 9.6 kb/s, 5 kHz deviation, 58.6 kHz RX bandwidth, 2 dBm and a
  // 64-bit preamble, so that AGC and AFC can settle before the sync word.
  // Identical on every node of the bench.
  int st = radio.beginFSK(CENTER_MHZ, 9.6, 5.0, 58.6, 2, 64);
  if (st != RADIOLIB_ERR_NONE) return st;
  radio.setCRC(true);
  // AFC. Without it the demodulator only locks on carriers within about one
  // deviation (5 kHz) of the tuned frequency, and every source further out is
  // lost without a trace. With AFC the chip measures the carrier in a wide
  // AFC bandwidth at the start of each reception and retunes to it, and the
  // applied correction is the carrier offset reported per frame.
  //  - 83.3 kHz AFC bandwidth covers the +28 kHz test attacker plus the
  //    crystal offset and the signal's own bandwidth.
  //  - AFC starts on the RSSI interrupt: a carrier far off-tune cannot be
  //    demodulated, so its preamble is never detected before AFC pulls it in.
  //  - The RSSI threshold must be above the noise floor (RadioLib's default
  //    of -127.5 dBm fires on noise), see rssiTrigDbm.
  //  - AfcAutoClearOn: every frame is measured from the nominal centre, not
  //    from the previous transmitter's offset.
  radio.setAFCBandwidth(83.3);
  radio.setAFC(true);
  radio.setAFCAGCTrigger(RADIOLIB_SX127X_RX_TRIGGER_RSSI_INTERRUPT);
  radio.setRSSIThreshold(rssiTrigDbm);
  radioMod->SPIsetRegValue(RADIOLIB_SX127X_REG_AFC_FEI, RADIOLIB_SX127X_AFC_AUTO_CLEAR_ON, 0, 0);
  // 2-byte preamble detector, as on the ground station.
  radioMod->SPIsetRegValue(RADIOLIB_SX127X_REG_PREAMBLE_DETECT,
      RADIOLIB_SX127X_PREAMBLE_DETECTOR_ON | RADIOLIB_SX127X_PREAMBLE_DETECTOR_2_BYTE |
      RADIOLIB_SX127X_PREAMBLE_DETECTOR_TOL);
  // Keep CRC-failed frames in the FIFO (CrcAutoClearOff) so that
  // handle_uplink() can count them (crc_bad) instead of losing them silently
  // inside the chip. A frame lost to bit errors is then told apart from one
  // that never synchronised.
  radioMod->SPIsetRegValue(RADIOLIB_SX127X_REG_PACKET_CONFIG_1,
      RADIOLIB_SX127X_CRC_AUTOCLEAR_OFF, 3, 3);
  radio.setDio0Action(onRx, RISING);
  return radio.startReceive();
}

/* Move the RSSI trigger with the received frames (see rssiTrigDbm). */
static void track_frame_rssi(float rssi) {
  frameRssiAvg = std::isnan(frameRssiAvg) ? rssi : 0.8f * frameRssiAvg + 0.2f * rssi;
  float want = std::max(rssiFloorDbm + FLOOR_MARGIN_DB, frameRssiAvg - FRAME_MARGIN_DB);
  want = std::min(-60.0f, std::max(-100.0f, want));
  if (fabsf(want - rssiTrigDbm) < 3.0f) return;   // no churn on small changes
  rssiTrigDbm = want;
  radio.setRSSIThreshold(rssiTrigDbm);
  radio.startReceive();
}

/* Carrier offset of the frame just received: RegAfcValue, the correction the
   chip applied at the start of this reception (signed 16 bit, step
   32 MHz / 2^19). The FEI register is not added: read after RxDone it
   averages payload bits and scatters by several kHz.                        */
static float carrier_offset_hz() {
  int16_t afc = (int16_t)((radioMod->SPIreadRegister(RADIOLIB_SX127X_REG_AFC_MSB) << 8) |
                           radioMod->SPIreadRegister(RADIOLIB_SX127X_REG_AFC_LSB));
  const float FSTEP = 32000000.0f / 524288.0f;
  return afc * FSTEP;
}

/* ═══════════════════════════ fingerprint whitelist ═══════════════════════
   The satellite's own ground stations, each bound to the carrier offset its
   transmitter uses. HnyProto.h explains why a callsign alone is not an
   identity. The table lives in flash so it survives a reset, and it is small
   on purpose: a member satellite talks to a handful of stations.

   Enrolment is a deliberate operator action ('A' after a known-good frame).
   A flight build would fill the table before launch and update it only
   through an authenticated uplink.                                          */
static void fp_save() {
  File f = LittleFS.open(FP_STORE, "w");
  if (!f) { Serial.println("{\"err\":\"fpallow open\"}"); return; }
  for (size_t i = 0; i < nFpAllow; i++)
    f.printf("%s,%.2f,%.2f,%u,%lu\n", fpAllow[i].call, fpAllow[i].bias_khz,
             fpAllow[i].tol_khz, fpAllow[i].conf,
             (unsigned long)fpAllow[i].hits);
  f.close();
}

static void fp_load() {
  nFpAllow = 0;
  File f = LittleFS.open(FP_STORE, "r");
  if (f) {
    while (f.available() && nFpAllow < FP_MAX) {
      String line = f.readStringUntil('\n');
      if (line.length() < 5) continue;
      FpAllow e = {};
      float bias = 0, tol = 0; unsigned conf = 0; unsigned long hits = 0;
      char call[10] = {0};
      if (sscanf(line.c_str(), "%9[^,],%f,%f,%u,%lu",
                 call, &bias, &tol, &conf, &hits) >= 4) {
        strncpy(e.call, call, sizeof(e.call) - 1);
        e.bias_khz = bias; e.tol_khz = tol;
        e.conf = (uint8_t)conf; e.hits = (uint32_t)hits;
        fpAllow[nFpAllow++] = e;
      }
    }
    f.close();
  }
  if (nFpAllow == 0) {
    // First boot: the operator's own station, enrolled at the offset it uses
    // on this bench (GS104 transmits on 0.0 kHz, see BENCH_GS in HnyProto.h).
    FpAllow e = {};
    strncpy(e.call, "GS104", sizeof(e.call) - 1);
    e.bias_khz = 0.0f; e.tol_khz = FP_ENROL_TOL_KHZ; e.conf = 90; e.hits = 0;
    fpAllow[nFpAllow++] = e;
    fp_save();
  }
}

static void fp_print() {
  Serial.printf("[wl] %u/%u entries\n", (unsigned)nFpAllow, FP_MAX);
  for (size_t i = 0; i < nFpAllow; i++) {
    char sig[18];
    hny_signature(fpAllow[i].call, fpAllow[i].bias_khz, sig, sizeof(sig));
    Serial.printf("[wl]  %-10s %-12s bias=%+.2f kHz tol=%.2f conf=%u hits=%lu\n",
                  fpAllow[i].call, sig, fpAllow[i].bias_khz, fpAllow[i].tol_khz,
                  fpAllow[i].conf, (unsigned long)fpAllow[i].hits);
  }
}

/* Enrol, or re-enrol, the transmitter of the last frame. Re-enrolling an
   existing callsign moves its entry instead of adding a second one: two
   entries for one callsign would widen the window an impersonator has to hit. */
static void fp_enroll(const char *src, float dev_khz) {
  for (size_t i = 0; i < nFpAllow; i++) {
    if (strcmp(fpAllow[i].call, src)) continue;
    fpAllow[i].bias_khz = dev_khz;
    fpAllow[i].tol_khz = FP_ENROL_TOL_KHZ;
    fpAllow[i].conf = 90;
    fpAllow[i].hits = 0;
    fp_save();
    Serial.printf("[wl] re-enrolled %s at %+.2f kHz\n", src, dev_khz);
    return;
  }
  if (nFpAllow >= FP_MAX) { Serial.println("[wl] table full"); return; }
  FpAllow e = {};
  strncpy(e.call, src, sizeof(e.call) - 1);
  e.bias_khz = dev_khz; e.tol_khz = FP_ENROL_TOL_KHZ; e.conf = 90; e.hits = 0;
  fpAllow[nFpAllow++] = e;
  fp_save();
  Serial.printf("[wl] enrolled %s at %+.2f kHz (tol %.2f)\n",
                src, dev_khz, FP_ENROL_TOL_KHZ);
}

/* ═══════════════════════════ common-mode Doppler estimate ════════════════
   The whitelist must be checked on the residual (the carrier offset with the
   pass Doppler removed), and the bench has no orbit model. It does not need
   one: every cooperating station pre-compensates the same pass profile, so
   subtracting each station's known bias from its measured offset leaves the
   common motion. The median of the last DOP_WIN such samples estimates it,
   and a fixed-frequency attacker is an outlier the median ignores.

   A flight board would take this value from its orbit propagator. With fewer
   than DOP_MIN_N samples the estimate is zero (fail-open): the residual is
   then the raw offset and the whitelist has less to say.                     */
static float dop_estimate_khz() { return (dopN >= DOP_MIN_N) ? dopEstKhz : 0.0f; }

static void dop_update(const char *src, float dev_khz) {
  float bias;
  if (!bench_bias_khz(src, &bias)) return;      // unknown callsign: no information
  dopWin[dopI] = dev_khz - bias;
  dopI = (dopI + 1) % DOP_WIN;
  if (dopN < DOP_WIN) dopN++;
  float tmp[DOP_WIN];
  memcpy(tmp, dopWin, sizeof(float) * dopN);
  for (uint8_t i = 1; i < dopN; i++) {          // insertion sort, n <= 8
    float v = tmp[i]; int8_t j = i - 1;
    while (j >= 0 && tmp[j] > v) { tmp[j + 1] = tmp[j]; j--; }
    tmp[j + 1] = v;
  }
  dopEstKhz = (dopN & 1) ? tmp[dopN / 2]
                         : 0.5f * (tmp[dopN / 2 - 1] + tmp[dopN / 2]);
}

/* ═══════════════════════════ records and LEDs ═════════════════════════════ */

/* Record identifier: SHA-256 over the frame's own fields, first 10 bytes. */
static void fingerprint(const Record &r, char *out21) {
  char feat[128];
  snprintf(feat, sizeof(feat), "%s|%.5f|%.1f|%s", r.src, r.freq_dev_khz, r.dop_hz, r.cmd);
  uint8_t d[32];
  mbedtls_sha256_context c; mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, (const uint8_t *)feat, strlen(feat));
  mbedtls_sha256_finish(&c, d); mbedtls_sha256_free(&c);
  for (int k = 0; k < 10; k++) snprintf(out21 + 2 * k, 3, "%02X", d[k]);
}

static void store_record(const Record &r) {
  File f = LittleFS.open(STORE, "a");
  if (!f) { Serial.println("{\"err\":\"store open\"}"); return; }
  f.write((const uint8_t *)&r, sizeof(Record));
  f.close();
  nStored++;
}

/* The verdict LEDs hold the last verdict until the next frame replaces it,
   so that frames arriving close together can still be read off the board. */
static void leds_off() {
  digitalWrite(PIN_LED, LOW);
  digitalWrite(PIN_LED_Y, LOW);
  digitalWrite(PIN_LED_G, LOW);
}

static void led_show(int pin) {
  leds_off();
  digitalWrite(pin, HIGH);
}

/* ═══════════════════════════ uplink: receive, score, store ═══════════════ */
static void handle_uplink() {
  rxRaw++;
  uint8_t buf[64];
  // RF metadata first, before the FIFO is read. getRSSI(false, true) reads
  // the instantaneous value without the startReceive()/standby() pair that
  // plain getRSSI() performs in FSK mode, which would measure the noise floor
  // after the frame instead of the frame.
  float ferr = carrier_offset_hz();
  float rssi = radio.getRSSI(false, true);
  int len = radio.getPacketLength();
  // PHY CRC, read from RegIrqFlags2 before readData() clears it: RadioLib
  // checks the CRC only in LoRa mode, so in FSK mode readData() reports
  // success for a failed frame. Such frames are counted and dropped, because
  // bits the radio itself rejects carry no trustworthy callsign or command.
  // (The malformed-packet indicator uses the AX.25 FCS, which the test
  // transmitter corrupts under a valid PHY CRC.)
  bool phy_crc_ok = (radio.getIRQFlags() >> 8) & RADIOLIB_SX127X_FLAG_CRC_OK;
  int st = radio.readData(buf, min(len, (int)sizeof(buf)));
  uint32_t nowMs = millis();
  float gap = haveLast ? (nowMs - lastRxMs) / 1000.0f : 99.0f;
  radio.startReceive();
  if (!phy_crc_ok || st != RADIOLIB_ERR_NONE) { rxCrcBad++; return; }
  track_frame_rssi(rssi);
  lastRxMs = nowMs; haveLast = true;
  if (len <= 0) return;

  char src[10] = {0}, dst[10] = {0}, info[48] = {0};
  size_t ilen = 0;
  bool fcs_ok = false;
  // Decode even when the AX.25 FCS is bad: the honeypot logs every frame
  // regardless of validity, and the malformed-packet indicator needs the
  // record. A false return means the frame is not an AX.25 UI frame at all.
  if (!ax25_parse(buf, len, src, sizeof(src), dst, sizeof(dst),
                  (uint8_t *)info, sizeof(info), &ilen, &fcs_ok)) {
    // No verdict is possible, so member mode fails open: a board that cannot
    // decide must never be the reason a satellite stops taking commands.
    if (mode == MODE_MEMBER) {
      led_show(PIN_LED_G);
      Serial.println("[mbr] undecodable frame -> ACCEPT (fail-open)");
    } else {
      Serial.printf("[rx?] undecodable len=%d st=%d rssi=%.1f ferr=%+.0f raw:",
                    len, st, rssi, ferr);
      for (int i = 0; i < len && i < 12; i++) Serial.printf(" %02X", buf[i]);
      Serial.println();
    }
    return;
  }

  // info = "<seq>|<cmd>"
  char *bar = strchr(info, '|');
  const char *cmd = bar ? bar + 1 : info;

  float dev_khz = (ferr - CALIB_HZ) / 1000.0f;

  strncpy(lastSrc, src, sizeof(lastSrc) - 1);
  lastDevKhz = dev_khz;
  haveLastPkt = true;

  /* The Doppler estimate is taken before this frame is added, so a frame
     cannot vouch for itself. Two quantities follow from it:
       resid_khz    the transmitter's own carrier bias with the common pass
                    Doppler removed: the identity behind the signature and
                    the whitelist;
       dopResidKhz  what remains after that station's known bias is removed
                    as well: the input of the Doppler-mismatch indicator.
                    Near zero for a station that tracks the pass, the whole
                    pass profile for one on a fixed frequency.
     A callsign without a known bias is treated as bias zero, the same rule
     the ground analysis uses.                                               */
  float dopKhz = dop_estimate_khz();
  float resid_khz = dev_khz - dopKhz;
  float knownBias = 0.0f;
  bench_bias_khz(src, &knownBias);
  float dopResidKhz = (dopN >= DOP_MIN_N) ? (resid_khz - knownBias) : 0.0f;
  dop_update(src, dev_khz);

  lastResidKhz = resid_khz;

  const FpAllow *wlHit = nullptr;
  WlState wl = fp_allow_check(fpAllow, nFpAllow, src, resid_khz, &wlHit);
  if (wl == WL_MATCH && wlHit) {
    // counted so that an entry that never matches is visible ('F');
    // written to flash lazily, not on every frame
    const_cast<FpAllow *>(wlHit)->hits++;
  }

  // ── member mode: a gate, not a sensor ─────────────────────────────────
  if (mode == MODE_MEMBER) {
    const BlockEntry *hit = nullptr;
    WlState wlv = WL_NONE;
    Verdict v = hny_verdict_fp(src, dev_khz, resid_khz, fpAllow, nFpAllow,
                               &hit, &wlv);
    // A flight board would drive a verdict line to the on-board computer;
    // the bench uses the LEDs. V_SPOOF_SUSPECT (one of our own callsigns from
    // a radio that is not the enrolled one, not on the blocklist) is still
    // accepted, fail-open, but marked amber.
    led_show(v == V_BLOCK ? PIN_LED
              : (v == V_ALLOW_OVERRIDE || v == V_SPOOF_SUSPECT) ? PIN_LED_Y
              : PIN_LED_G);
    Serial.printf("[mbr] %-6s %-20s dev=%+6.1fkHz wl=%s -> %-6s %s\n", src, cmd,
                  dev_khz,
                  wlv == WL_MATCH ? "match" : wlv == WL_MISMATCH ? "MISMATCH" : "none",
                  v == V_BLOCK ? "BLOCK" : "ACCEPT",
                  v == V_ALLOW_OVERRIDE ? "(blocklist hit, allowlist wins)"
                  : v == V_SPOOF_SUSPECT ? "(allowlisted callsign, wrong radio)"
                  : (hit ? "(blocklist)" : ""));
    return;                       // no score, no record, nothing downlinked
  }

  Record r; memset(&r, 0, sizeof(r));
  r.t_ms = nowMs;
  strncpy(r.src, src, sizeof(r.src) - 1);
  strncpy(r.cmd, cmd, sizeof(r.cmd) - 1);
  r.freq_dev_khz = dev_khz;
  hny_signature(src, resid_khz, r.sig, sizeof(r.sig));
  r.wl = (uint8_t)wl;
  // Doppler residual against the common-mode estimate. The ground station
  // fits the pass properly and replaces it with its own value; carrying the
  // onboard one lets the two be compared.
  r.dop_hz = dopResidKhz * 1000.0f;
  r.rssi = rssi;
  r.crc_ok = (phy_crc_ok && fcs_ok) ? 1 : 0;
  r.gap_s = gap;
  uint32_t heapBefore = ESP.getFreeHeap();
  uint32_t t0 = micros();
  hny_score(r);
  fingerprint(r, r.fp);
  uint32_t t1 = micros();
  store_record(r);
  uint32_t t2 = micros();
  perf_add(t1 - t0, t2 - t1, (int32_t)ESP.getFreeHeap() - (int32_t)heapBefore);

  bool known = !strcmp(r.cls, "known");
  bool susp  = !strcmp(r.cls, "suspicious");
  led_show((r.flagged || (!known && !susp)) ? PIN_LED
            : susp ? PIN_LED_Y : PIN_LED_G);

  Serial.printf("[rx] %-6s %-20s dev=%+6.1f res=%+6.1f dop=%+6.0fHz rssi=%.0f score=%2d %-10s %s%s%s\n",
                r.src, r.cmd, r.freq_dev_khz, resid_khz, r.dop_hz, r.rssi,
                r.score, r.cls,
                r.crc_ok ? "" : "BAD-FCS ", r.flagged ? "FLAG " : "",
                r.wl == WL_MISMATCH ? "WL-MISMATCH" : r.wl == WL_MATCH ? "WL-OK" : "");
}

/* ═══════════════════════════ downlink to the ground station ══════════════ */
static void downlink() {
  File f = LittleFS.open(STORE, "r");
  if (!f || f.size() == 0) { Serial.println("[dl] nothing stored"); if (f) f.close(); return; }
  digitalWrite(PIN_LED_B, HIGH);          // blue for the whole downlink
  uint32_t total = f.size() / sizeof(Record), sent = 0;
  Serial.printf("[dl] downlinking %lu records to CTIGS ...\n", (unsigned long)total);
  radio.setFrequency(CENTER_MHZ);
  Record r;
  while (f.read((uint8_t *)&r, sizeof(Record)) == sizeof(Record)) {
    /* Records go out packed (RecordWire, 42 bytes, 60 on air with AX.25):
       the receiver's FIFO holds 64 bytes, and a CSV record would not fit.
       The residual the signature is built from is recovered from the stored
       Doppler residual and the station's known bias.                       */
    float bias = 0.0f;
    bench_bias_khz(r.src, &bias);
    float resid_khz = bias + r.dop_hz / 1000.0f;
    RecordWire w;
    record_pack(r, resid_khz, w);
    uint8_t frame[80];
    size_t n = ax25_build(frame, sizeof(frame), "CTIGS", 0, "HNY1", 0,
                          (uint8_t *)&w, sizeof(w));
    int st = radio.transmit(frame, n);
    if (st == RADIOLIB_ERR_NONE) sent++;
    // Gap for the ground station, which re-arms AFC/AGC after every frame
    // and can take up to 60 ms to recover from a false start.
    delay(300);
  }
  f.close();
  digitalWrite(PIN_LED_B, LOW);
  // DIO0 toggles during transmission: restart reception and drop the flag so
  // that the tail of our own frame is not read back as an uplink frame.
  radio.startReceive();
  rxFlag = false;
  Serial.printf("[dl] done: %lu/%lu sent\n", (unsigned long)sent, (unsigned long)total);
}

/* ═══════════════════════════ COM transmitter blanking ════════════════════
   Parks the receiver for as long as COM_TX_ACTIVE is asserted; acts only on
   an edge. The blanked time is counted ('S') rather than written into the
   record store: a long gap on the next real frame plus these counters show
   that the silence was self-inflicted, not a quiet channel.                */
static void service_tx_blanking() {
  bool tx = (digitalRead(PIN_TX_ACTIVE) == TX_ACTIVE_LEVEL);
  if (tx == rxBlanked) return;                 // no edge
  rxBlanked = tx;
  if (tx) {
    radio.standby();
    rxFlag = false;                            // drop a half-served interrupt
    blankT0Ms = millis();
    blankN++;
    Serial.println("[hny] COM TX — receiver blanked");
  } else {
    blankMsTotal += millis() - blankT0Ms;
    radio.startReceive();
    Serial.printf("[hny] COM TX done — listening again (%lu ms)\n",
                  (unsigned long)(millis() - blankT0Ms));
  }
}

/* ═══════════════════════════ status report ('S') ══════════════════════════ */
static void status() {
  File f = LittleFS.open(STORE, "r");
  uint32_t n = (f && f.size()) ? f.size() / sizeof(Record) : 0;
  if (f) f.close();

  // integer microseconds; all zero until a frame has been measured
  uint32_t score_avg = perf.n ? perf.score_sum_us / perf.n : 0;
  uint32_t store_avg = perf.n ? perf.store_sum_us / perf.n : 0;

  Serial.printf("{\"evt\":\"status\",\"stored\":%lu,\"fs_used\":%u,\"fs_total\":%u,"
                "\"wl_entries\":%u,\"rx_raw\":%lu,\"rx_stuck\":%lu,\"radio_reinit\":%lu,"
                "\"rx_mode_fix\":%lu,\"crc_bad\":%lu,\"rx_polled\":%lu,\"opmode\":%u,\"irq\":%u,"
                "\"rssi_floor\":%.1f,\"rssi_trig\":%.1f,\"frame_rssi\":%.1f,\"blank_n\":%lu,\"blank_ms\":%lu,\"perf_n\":%lu,"
                "\"score_avg_us\":%lu,\"score_max_us\":%lu,"
                "\"store_avg_us\":%lu,\"store_max_us\":%lu,"
                "\"heap_delta_min\":%ld,\"heap_free\":%u,\"heap_min_free\":%u,"
                "\"stack_hwm\":%u}\n",
                (unsigned long)n, LittleFS.usedBytes(), LittleFS.totalBytes(),
                (unsigned)nFpAllow,
                (unsigned long)rxRaw, (unsigned long)rxStuck,
                (unsigned long)radioReinit, (unsigned long)rxModeFix,
                (unsigned long)rxCrcBad, (unsigned long)rxPolled,
                (unsigned)radioMod->SPIgetRegValue(RADIOLIB_SX127X_REG_OP_MODE),
                (unsigned)radio.getIRQFlags(), rssiFloorDbm, rssiTrigDbm, frameRssiAvg,
                (unsigned long)blankN,
                (unsigned long)blankMsTotal, (unsigned long)perf.n,
                (unsigned long)score_avg, (unsigned long)perf.score_max_us,
                (unsigned long)store_avg, (unsigned long)perf.store_max_us,
                (long)perf.heap_delta_min, ESP.getFreeHeap(), ESP.getMinFreeHeap(),
                (unsigned)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)));
}

/* ═══════════════════════════ radio power: INA219 ('P') ═══════════════════
   The radio's supply runs ESP32 3V3 -> INA219 VIN+ -> shunt -> VIN- -> Ra-01,
   so the shunt carries the radio's current and nothing else. Registers are
   read directly over I2C. With the module's 0.1 ohm shunt the current
   resolution is 0.1 mA: fine for receive, standby and transmit, too coarse
   for the SX1278's sleep current, which reads as zero. Configuration:
   +-40 mV shunt range, 128-sample averaging (68 ms per conversion).        */
static const uint8_t INA_ADDR = 0x40;
static const float   SHUNT_OHM = 0.1f;
static bool inaOk = false;

static bool ina_write(uint8_t reg, uint16_t v) {
  Wire.beginTransmission(INA_ADDR);
  Wire.write(reg); Wire.write(v >> 8); Wire.write(v & 0xFF);
  return Wire.endTransmission() == 0;
}

static bool ina_read(uint8_t reg, uint16_t &v) {
  Wire.beginTransmission(INA_ADDR);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom(INA_ADDR, (uint8_t)2) != 2) return false;
  v = (uint16_t)(Wire.read() << 8); v |= Wire.read();
  return true;
}

static float ina_ma() {                           // radio supply current
  uint16_t r;
  return ina_read(0x01, r) ? (int16_t)r * 0.01f / SHUNT_OHM : NAN;
}

static float ina_bus_v() {                        // voltage at the radio (VIN-)
  uint16_t r;
  return ina_read(0x02, r) ? (r >> 3) * 0.004f : NAN;
}

// mean current and voltage over n conversions, after the state has settled
static void ina_measure(int n, float &ma, float &v) {
  delay(150);
  float si = 0, sv = 0;
  for (int i = 0; i < n; i++) { delay(70); si += ina_ma(); sv += ina_bus_v(); }
  ma = si / n; v = sv / n;
}

/* Listening, standby, sleep and a 2 dBm carrier (0.5 s, the link's own power)
   in turn, then back to receive.                                            */
static void power_profile() {
  if (!inaOk) { Serial.println("{\"err\":\"ina219 not found\"}"); return; }
  float rxI, rxV, sbI, sbV, slI, slV, txI, txV;
  radio.startReceive();  ina_measure(14, rxI, rxV);
  radio.standby();       ina_measure(8, sbI, sbV);
  radio.sleep();         ina_measure(8, slI, slV);
  radio.standby();
  radio.transmitDirect(); ina_measure(5, txI, txV);
  radio.standby();
  radio_config();
  Serial.printf("{\"evt\":\"power\",\"rx_ma\":%.2f,\"rx_v\":%.3f,\"rx_mw\":%.1f,"
                "\"standby_ma\":%.2f,\"standby_v\":%.3f,\"sleep_ma\":%.2f,"
                "\"tx2dbm_ma\":%.2f,\"tx2dbm_v\":%.3f,\"tx2dbm_mw\":%.1f}\n",
                rxI, rxV, rxI * rxV, sbI, sbV, slI, txI, txV, txI * txV);
}

/* ═══════════════════════════ in-band scan ('Q') ═══════════════════════════
   Steps the receiver across 433.40-433.60 MHz in 2 kHz steps and reports the
   mean and peak RSSI at each, so that a spur near the channel shows up as a
   peak. Run with every transmitter silent; the receiver is reconfigured
   afterwards.                                                               */
static void band_scan() {
  Serial.println("[scan] start: 433.400-433.600 MHz, 2 kHz steps, 40 samples each");
  for (int k = -100; k <= 100; k += 2) {
    radio.standby();
    radio.setFrequency(CENTER_MHZ + k / 1000.0f);
    radio.startReceive();
    delay(3);
    float sum = 0, mx = -200;
    for (int i = 0; i < 40; i++) {
      float r = radio.getRSSI(false, true);
      sum += r; if (r > mx) mx = r;
      delayMicroseconds(500);
    }
    Serial.printf("[scan] %+4d kHz mean %.1f max %.1f\n", k, sum / 40, mx);
  }
  radio_config();
  Serial.println("[scan] done, receiver back on 433.500 MHz");
}

/* ═══════════════════════════ receiver watchdogs ══════════════════════════ */

/* AFC and AGC run once, on the RSSI interrupt, and then hold. If that start
   does not end in a frame (noise above the threshold, the tail of a frame, a
   preamble found at the wrong AFC setting), the receiver keeps waiting for a
   sync word with the wrong frequency and gain. Two guards restart reception,
   which re-arms AFC/AGC:
    - RSSI start with no sync match within 60 ms. The RSSI flag is sticky, so
      the window must be longer than one frame (under 60 ms on air) or the
      guard restarts a healthy receiver between frames.
    - Sync match with no RxDone within 150 ms: a mistuned or clipped frame can
      leave the chip waiting for a payload that never completes (rx_stuck). */
static void rx_watchdog() {
  static uint32_t rssiSinceMs = 0, syncSinceMs = 0;
  if (rxBlanked) { rssiSinceMs = syncSinceMs = 0; return; }
  // poll once a millisecond: continuous register reads keep SPI clocking
  // next to a receiver that is demodulating
  static uint32_t lastPollUs = 0;
  if (micros() - lastPollUs < 1000) return;
  lastPollUs = micros();
  uint16_t irq = radio.getIRQFlags();
  uint8_t f1 = irq & 0xFF, f2 = irq >> 8;           // RegIrqFlags1 / 2
  // a completed frame whose DIO0 edge was missed is served from the flag
  if ((f2 & RADIOLIB_SX127X_FLAG_PAYLOAD_READY) && !rxFlag) {
    rssiSinceMs = syncSinceMs = 0; rxPolled++; rxFlag = true; return;
  }
  bool rssi = f1 & RADIOLIB_SX127X_FLAG_RSSI;
  bool sync = f1 & RADIOLIB_SX127X_FLAG_SYNC_ADDRESS_MATCH;
  if (sync) {
    rssiSinceMs = 0;
    if (!syncSinceMs) { syncSinceMs = millis() | 1; return; }
    if (millis() - syncSinceMs >= 150) { syncSinceMs = 0; rxStuck++; radio.startReceive(); }
    return;
  }
  syncSinceMs = 0;
  if (!rssi) { rssiSinceMs = 0; return; }
  if (!rssiSinceMs) { rssiSinceMs = millis() | 1; return; }
  if (millis() - rssiSinceMs >= 60) { rssiSinceMs = 0; radio.startReceive(); }
}

/* Two ways the receiver goes deaf without raising a flag the watchdog sees,
   checked once a second:
    - A supply dip resets the SX1278 but not the ESP32. The chip comes back
      in standby at its reset defaults; the configured bitrate register reads
      0x0D, the default does not.
    - The chip keeps its configuration but has dropped to standby or sleep.
   Frequency-synthesis RX (OpMode 0x0C) is not a fault: with the RSSI trigger
   a listening receiver sits there between frames.                          */
static void radio_health() {
  static uint32_t lastMs = 0;
  if (rxBlanked || rxFlag || millis() - lastMs < 1000) return;
  lastMs = millis();
  if (radioMod->SPIgetRegValue(RADIOLIB_SX127X_REG_BITRATE_MSB) != 0x0D) {
    radioReinit++;
    int st = radio_config();
    Serial.printf("[hny] radio lost its configuration, reconfigured (st=%d)\n", st);
    return;
  }
  uint8_t mode = radioMod->SPIgetRegValue(RADIOLIB_SX127X_REG_OP_MODE) & 0x07;
  if (mode != RADIOLIB_SX127X_RX && mode != RADIOLIB_SX127X_FSRX) {
    rxModeFix++;
    radio.startReceive();
  }
}

/* ═══════════════════════════ setup and loop ═══════════════════════════════ */
void setup() {
  Serial.begin(115200);
  delay(800);
  pinMode(PIN_LED, OUTPUT);
  pinMode(PIN_LED_G, OUTPUT);
  pinMode(PIN_LED_Y, OUTPUT);
  pinMode(PIN_LED_B, OUTPUT);
  pinMode(PIN_BOOT, INPUT_PULLUP);
  pinMode(PIN_TX_ACTIVE, INPUT_PULLUP);
  SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_NSS);
  Wire.begin(PIN_SDA, PIN_SCL);
  // INA219: 16 V bus range, PGA /1 (+-40 mV), 12-bit bus, 128-sample shunt, continuous
  inaOk = ina_write(0x00, 0x01FF);
  Serial.printf("[hny] INA219 %s\n", inaOk ? "found at 0x40 (radio supply monitor)" : "not found");

  if (!LittleFS.begin(true)) Serial.println("{\"err\":\"littlefs\"}");
  if (LittleFS.exists(STORE_LEGACY)) LittleFS.remove(STORE_LEGACY);
  fp_load();
  File f = LittleFS.open(STORE, "r");
  nStored = (f && f.size()) ? f.size() / sizeof(Record) : 0;
  if (f) f.close();

  int st = radio_config();
  if (st != RADIOLIB_ERR_NONE) { Serial.printf("{\"err\":\"radio %d\"}\n", st); while (1) delay(1000); }
  // Noise floor: median of 1 s of instantaneous RSSI with the receiver
  // listening. Valid even with traffic on air, which occupies a few percent
  // of the time.
  {
    static float v[200];
    for (int i = 0; i < 200; i++) { v[i] = radio.getRSSI(false, true); delay(5); }
    std::sort(v, v + 200);
    rssiFloorDbm = v[100];
    rssiTrigDbm = std::min(-60.0f, std::max(-100.0f, rssiFloorDbm + FLOOR_MARGIN_DB));
    radio.setRSSIThreshold(rssiTrigDbm);   // radio_config() keeps it from here on
    radio.startReceive();
  }
  Serial.printf("[hny] noise floor %.1f dBm, RSSI threshold %.1f dBm\n", rssiFloorDbm, rssiTrigDbm);
  Serial.printf("{\"evt\":\"ready\",\"role\":\"hny\",\"stored\":%lu}\n", (unsigned long)nStored);
  Serial.printf("[hny] mode: %s — 'D' downlink, 'S' status, 'E' erase, "
                "'R' reset perf, 'M' toggle honeypot/member, 'F' whitelist, "
                "'A' enrol last source, 'X' clear whitelist\n", mode_name());
  fp_print();
}

void loop() {
  service_tx_blanking();
  if (rxFlag) { rxFlag = false; if (!rxBlanked) handle_uplink(); }
  rx_watchdog();
  radio_health();

  if (Serial.available()) {
    char c = Serial.read();
    if (c == 'D' || c == 'd') downlink();
    else if (c == 'S' || c == 's') status();
    else if (c == 'Q' || c == 'q') band_scan();
    else if (c == 'P' || c == 'p') power_profile();
    else if (c == 'E' || c == 'e') { LittleFS.remove(STORE); nStored = 0; Serial.println("[hny] store erased"); }
    else if (c == 'F' || c == 'f') { fp_save(); fp_print(); }
    else if (c == 'A' || c == 'a') {
      if (!haveLastPkt) Serial.println("[wl] no packet heard yet");
      else fp_enroll(lastSrc, lastResidKhz);
    }
    else if (c == 'X' || c == 'x') {
      nFpAllow = 0; fp_save();
      Serial.println("[wl] whitelist cleared — fail-open until re-enrolled");
    }
    else if (c == 'R' || c == 'r') { memset(&perf, 0, sizeof(perf)); Serial.println("[hny] perf counters reset"); }
    else if (c == 'M' || c == 'm') {
      mode = (mode == MODE_MEMBER) ? MODE_HONEYPOT : MODE_MEMBER;
      leds_off();
      Serial.printf("[hny] mode: %s\n", mode_name());
    }
  }
  if (digitalRead(PIN_BOOT) == LOW) { delay(50); if (digitalRead(PIN_BOOT) == LOW) { downlink(); while (digitalRead(PIN_BOOT) == LOW) delay(10); } }
}
