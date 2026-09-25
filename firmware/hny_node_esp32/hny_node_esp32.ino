/* ═══════════════════════════════════════════════════════════════════════
   PHASE 2 — honeypot node: ESP-32S + SX1278

   Captures the uplink (AX.25 UI frames from gs_uplink_pico), measures per-
   packet RF metadata, runs the onboard detection (HnyProto — identical math to
   platform/detector.py), and STORES every CTI record in on-board flash
   (LittleFS). This is what the honeypot "remembers".

   PHASE 3 downlink: type 'D' in the serial monitor (or press BOOT/IO0). The
   node reads every stored record and transmits it as an AX.25 UI frame
   HNY1 -> CTIGS, where the ground station (ground_station/gs_cti_pi) receives it and
   forwards it to the server. 'S' prints status, 'E' erases the store.

   Library: RadioLib + HnyProto. Board: ESP32 Dev Module.
   ═══════════════════════════════════════════════════════════════════════ */
#include <RadioLib.h>
#include <LittleFS.h>
#include <mbedtls/sha256.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <HnyProto.h>
#include <Wire.h>
#include <algorithm>

#define PIN_SCK 18
#define PIN_MISO 19
#define PIN_MOSI 23
#define PIN_NSS 5
#define PIN_RST 14
#define PIN_DIO0 26
#define PIN_LED 32            // red   — flagged / attacker   (300 R)
#define PIN_LED_G 16           // green — known GS              (300 R, RX2)
#define PIN_LED_Y 17           // amber — suspicious            (200 R, TX2)
#define PIN_LED_B 4            // blue  — downlink in progress  (200 R)
#define PIN_BOOT 0
#define PIN_SDA 21             // INA219 (radio supply monitor)
#define PIN_SCL 22
/* COM_TX_ACTIVE — the satellite's main radio asserts this while it beacons or
   downlinks. The detection board is receive-only, but the COM transmitter sits
   centimetres away in the same 435-438 MHz band at 1-2 W, so its carrier
   reaches this receiver far above its maximum input level. The receiver is
   therefore parked in standby for the whole transmission.
   Active LOW with an internal pull-up, so an unconnected pin reads "not
   transmitting" and the bench runs without the wire. Flip TX_ACTIVE_LEVEL for
   a COM radio that drives the line high. IO25 is free on this bench.        */
#define PIN_TX_ACTIVE 25
#define TX_ACTIVE_LEVEL LOW
static Module *radioMod = new Module(PIN_NSS, PIN_DIO0, PIN_RST, RADIOLIB_NC);
SX1278 radio = radioMod;   // radioMod kept for raw register access (AFC)

static const float CENTER_MHZ = 433.5f;
// Two-crystal offset, measured 2026-09-25 on 58 Doppler-free link-test frames
// at 0, +-4, +-8, +24 and +28 kHz (tools/link_test_pico): the AFC reading
// sat 0.57 kHz below the applied offset with the previous +3.30 kHz, so the
// offset is +2.73 kHz; scatter about it is 0.26 kHz (1 sd), 53 of 58 frames
// within +-0.4 kHz. It was -3.13 kHz on 2026-09-22, before both radio modules
// were resoldered — re-measure whenever a module is reworked or swapped.
static const float CALIB_HZ   = 2730.0f;
/* AFC/AGC start threshold. It has two limits, and a fixed value does not
   survive moving the boards (2026-09-25, same firmware throughout):
    - above the noise floor, or noise starts AFC cycles: FLOOR_MARGIN_DB;
    - close enough below the frames that AGC is set on the settled carrier
      and not on the transmitter's power ramp: FRAME_MARGIN_DB. With frames
      at -46 dBm a -89 dBm threshold (floor + 15) let 2-3 of 10 through —
      sync matched, then the length byte came out corrupted — while -75 dBm
      took 8 of 10 in the same position.
   So the threshold starts at floor + FLOOR_MARGIN_DB (measured at boot) and
   follows the received frames: an average of their RSSI minus
   FRAME_MARGIN_DB, never below the floor limit.                          */
static const float FLOOR_MARGIN_DB = 15.0f;
static const float FRAME_MARGIN_DB = 30.0f;
static float rssiTrigDbm = -75.0f;      // replaced at boot, then tracks the frames
static float rssiFloorDbm = NAN;
static float frameRssiAvg = NAN;        // exponential average of received frames

static void track_frame_rssi(float rssi) {
  frameRssiAvg = std::isnan(frameRssiAvg) ? rssi : 0.8f * frameRssiAvg + 0.2f * rssi;
  float want = std::max(rssiFloorDbm + FLOOR_MARGIN_DB, frameRssiAvg - FRAME_MARGIN_DB);
  want = std::min(-60.0f, std::max(-100.0f, want));
  if (fabsf(want - rssiTrigDbm) < 3.0f) return;   // no churn on small changes
  rssiTrigDbm = want;
  radio.setRSSIThreshold(rssiTrigDbm);
  radio.startReceive();
}
// The record layout gained sig[] and wl, so the store is versioned by name:
// a file written by the older firmware has a different stride and would be
// read back as garbage. The old one is deleted at boot rather than migrated —
// it is bench data, and the flash is small.
static const char *STORE = "/records2.bin";
static const char *STORE_LEGACY = "/records.bin";
static const char *FP_STORE = "/fpallow.csv";

/* ═══════════ fingerprint whitelist (onboard) ═══════════════════════════
   The satellite's own ground stations, bound to the carrier they transmit on.
   HnyProto.h explains why a callsign alone is not an identity; this is the
   table that turns "GS104 says so" into "the radio we enrolled as GS104 says
   so". It lives in flash so it survives a reset, and it is small on purpose:
   a member satellite talks to a handful of stations, and every extra entry is
   another way in.

   Enrolment is a deliberate, operator-driven act on the bench ('A' after a
   known-good packet). On a flight build the same table would be filled from
   the ground before launch and updated by an authenticated uplink.        */
#define FP_MAX 8
static FpAllow fpAllow[FP_MAX];
static size_t  nFpAllow = 0;
static const float FP_ENROL_TOL_KHZ = 1.5f;   // temperature + ageing margin
                                              // (applied to the RESIDUAL, so it
                                              // does not have to cover Doppler)

// the last packet seen, so 'A' can enrol what was just heard
static char  lastSrc[10] = {0};
static float lastDevKhz   = 0.0f;
static float lastResidKhz = 0.0f;   // what the whitelist is enrolled against
static bool  haveLastPkt = false;

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
    // on this bench (HnyProto.h BENCH_GS: GS104 transmits on 0.0 kHz).
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

/* Enrol (or re-enrol) the transmitter of the last packet. Re-enrolling an
   existing callsign moves its bias instead of adding a second entry: two
   entries for one callsign would quietly widen the window an attacker has to
   hit, which is the opposite of the point.                                */
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

/* ═══════════ onboard common-mode Doppler estimate ══════════════════════
   The whitelist has to be checked on the residual, not on the raw carrier,
   and the bench board has no orbit model to compute the pass Doppler with.
   It does not need one: every cooperative station pre-compensates the SAME
   profile, so their carriers move together. Subtracting each station's known
   bias from its measured offset leaves that common motion, and the median
   over a short window is a robust estimate of it — an attacker transmitting
   on a fixed frequency contributes an outlier the median ignores, which is
   also why the median is used rather than the mean.

   On a flight board the estimate comes from the orbit propagator instead;
   this is the bench substitute for it, and it is deliberately fail-open: with
   fewer than DOP_MIN_N samples the residual falls back to the raw offset and
   the whitelist simply has less to say.                                   */
#define DOP_WIN 8
#define DOP_MIN_N 3
static float    dopWin[DOP_WIN];
static uint8_t  dopN = 0, dopI = 0;
static float    dopEstKhz = 0.0f;

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

/* Board mode (paper 6.1). HONEYPOT is the sensor this bench was built around:
   it scores, stores and later downlinks every packet. MEMBER turns the board
   into the accept/block gate a member satellite runs: it answers the OBC with
   a verdict from the CTI lists and stores NOTHING — members "send nothing
   back" (3.1). Toggle with 'M'; the bench demonstrates blocklist-based
   blocking only, which is the scope the paper sets for it (7).            */
enum Mode : uint8_t { MODE_HONEYPOT = 0, MODE_MEMBER = 1 };
static Mode mode = MODE_HONEYPOT;

static const char *mode_name() {
  return mode == MODE_MEMBER ? "member" : "honeypot";
}

volatile bool rxFlag = false;
// Every RxDone, parsed or not. perf.n only counts frames that made it
// through ax25_parse, so it cannot tell "nothing on air" from
// "arriving but undecodable". This can.
static uint32_t rxRaw = 0;
static uint32_t rxStuck = 0;     // RX restarts after a sync match that never completed
static uint32_t radioReinit = 0; // radio found at reset defaults and reconfigured
static uint32_t rxModeFix = 0;   // radio found in standby/sleep, receiver restarted
static uint32_t rxCrcBad = 0;    // frames that failed the PHY CRC, dropped
static uint32_t rxPolled = 0;    // packets found by polling PayloadReady (no DIO0 edge)
void IRAM_ATTR onRx() { rxFlag = true; }
static uint32_t lastRxMs = 0;
static bool haveLast = false;
static uint32_t nStored = 0;
static bool     rxBlanked   = false;   // receiver parked while COM transmits
static uint32_t blankT0Ms   = 0;       // start of the current blanking window
static uint32_t blankN      = 0;       // how many windows since boot
static uint32_t blankMsTotal = 0;      // total blanked time

/* ── bench instrumentation (Table 7, rows 1-2) ──────────────────────────
   Measures THIS chip, so it has to live on-chip; it is not part of the
   detection path (final analysis stays on the ground, paper 6.2).
   Scoring and the flash write are timed apart: the LittleFS write is one
   to two orders of magnitude slower and would otherwise hide the figure
   the paper actually asks for.                                          */
struct Perf {
  uint32_t n;                        // packets measured
  uint32_t score_sum_us, score_max_us;   // hny_score() + fingerprint()
  uint32_t store_sum_us, store_max_us;   // store_record() — flash
  int32_t  heap_delta_min;           // most negative free-heap change seen
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

// Carrier offset of the packet just received: RegAfcValue, the correction
// the chip applied at the start of this reception (signed 16-bit, Fstep =
// 32 MHz / 2^19). FEI read after RxDone is NOT added: on fixed-frequency
// frames AFC alone landed within ~0.3 kHz, AFC + FEI scattered by +-2-4 kHz,
// because FEI by then averages payload bits rather than preamble.
static float carrier_offset_hz() {
  int16_t afc = (int16_t)((radioMod->SPIreadRegister(RADIOLIB_SX127X_REG_AFC_MSB) << 8) |
                           radioMod->SPIreadRegister(RADIOLIB_SX127X_REG_AFC_LSB));
  const float FSTEP = 32000000.0f / 524288.0f;
  return afc * FSTEP;
}

/* Verdict LEDs hold the last verdict until the next packet replaces it.
   A one-second blink was tried first, but two frames 0.9 s apart (UNK971
   then GS107) made the first verdict vanish before it could be read.     */
static void leds_off() {
  digitalWrite(PIN_LED, LOW);
  digitalWrite(PIN_LED_Y, LOW);
  digitalWrite(PIN_LED_G, LOW);
}

static void led_show(int pin) {
  leds_off();
  digitalWrite(pin, HIGH);
}

// ── PHASE 2: receive + score + store ────────────────────────────────────
static void handle_uplink() {
  rxRaw++;
  uint8_t buf[64];
  // RF metadata FIRST, before the FIFO read and without touching the mode.
  // In FSK RadioLib's plain getRSSI() calls getRSSI(true, false), which does
  // startReceive() -> read a LIVE RegRssiValue -> standby(). By then the
  // packet is gone, so the "RSSI" is the ambient noise floor, and the
  // following getFrequencyError() reads FEI out of a standby chip, which is
  // always 0.0 — killing both the frequency indicator (HnyProto.h:236) and
  // the fuzzy bias match (HnyProto.h:246). getRSSI(false, true) asks for the
  // instant value and skips the receive/standby pair.
  // Caveat: this is still a few hundred us after RxDone. A true per-packet
  // RSSI in FSK has to be latched at sync-address detect, i.e. inside onRx.
  float ferr = carrier_offset_hz();
  float rssi = radio.getRSSI(false, true);
  int len = radio.getPacketLength();
  // PHY CRC, read from RegIrqFlags2 before readData() clears it: RadioLib
  // checks the CRC only in LoRa mode, so in FSK readData() returns success
  // for a failed frame. With CrcAutoClearOff (radio_config) failed frames do
  // reach us; they are counted and dropped — a frame whose bits the radio
  // itself rejects carries no trustworthy callsign or command. The
  // malformed-packet indicator rides on the AX.25 FCS, which the transmitter
  // corrupts under a valid PHY CRC.
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
  // Decode even when the FCS is bad: the paper has the node log every packet
  // "regardless of validity" (3.1), and the malformed-packet indicator can
  // only fire if the record exists. A false return here means the frame is
  // not a UI frame for us at all (too short / wrong shape), not that it is
  // corrupt — that one we do drop.
  if (!ax25_parse(buf, len, src, sizeof(src), dst, sizeof(dst),
                  (uint8_t *)info, sizeof(info), &ilen, &fcs_ok)) {
    // Undecodable: no verdict is possible, so member mode fails OPEN (6.1) —
    // a board that cannot decide must never be the reason a satellite stops
    // taking commands.
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

  /* Estimated BEFORE this frame is folded in, so a frame cannot vouch for
     itself. Two quantities come out of it:
       resid_khz     the transmitter's own carrier bias, once the common pass
                     Doppler is removed — the identity the signature and the
                     whitelist are built on;
       dopResidKhz   what is left after that station's KNOWN bias is removed
                     as well — the Doppler-mismatch indicator (HnyProto.h
                     DOPP_RESID_HZ_TH). Near zero for a station that tracks
                     the pass, the whole pass profile for one transmitting on
                     a fixed frequency.
     A callsign the bench does not run has no known bias, so its bias is taken
     as zero — the same convention the ground analysis uses, which keeps the
     two tiers computing the same number rather than two similar ones.    */
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
    // hits are counted in the table so an enrolment that never matches is
    // visible as such; written back lazily, not on every packet
    const_cast<FpAllow *>(wlHit)->hits++;
  }

  // ── MEMBER MODE: gate, not sensor ────────────────────────────────────
  if (mode == MODE_MEMBER) {
    const BlockEntry *hit = nullptr;
    WlState wlv = WL_NONE;
    Verdict v = hny_verdict_fp(src, dev_khz, resid_khz, fpAllow, nFpAllow,
                               &hit, &wlv);
    // On the flight board this drives the VERDICT stack-bus line and a CAN
    // message; on the bench it is the LEDs.
    /* V_SPOOF_SUSPECT: one of our own callsigns arrived from a radio that is
       not the enrolled one, and nothing on the blocklist matched. The board
       still fails open — it accepts — but it says so, and the amber LED marks
       it, because this is the case the whitelist exists to make visible.  */
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
  /* Doppler residual, computed against the common-mode estimate rather than
     an orbit model. The ground fits the pass properly and overwrites this
     column with its own value; carrying it lets the two be compared. Zero
     while the estimator has too few samples, which leaves the indicator
     silent instead of guessing.                                          */
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

// ── PHASE 3: downlink stored records to the CTI ground station ──────────
static void downlink() {
  File f = LittleFS.open(STORE, "r");
  if (!f || f.size() == 0) { Serial.println("[dl] nothing stored"); if (f) f.close(); return; }
  digitalWrite(PIN_LED_B, HIGH);          // blue on for the whole downlink
  uint32_t total = f.size() / sizeof(Record), sent = 0;
  Serial.printf("[dl] downlinking %lu records to CTIGS ...\n", (unsigned long)total);
  radio.setFrequency(CENTER_MHZ);
  Record r;
  while (f.read((uint8_t *)&r, sizeof(Record)) == sizeof(Record)) {
    /* Packed, not CSV: the receiver's FSK FIFO holds 64 bytes and a CSV
       record makes a 122-byte frame, which is never delivered (HnyProto.h,
       "downlink wire record"). 42 bytes packed + 18 of AX.25 = 60 on air.
       The residual the signature is built from is recovered from the stored
       record: the honeypot wrote its Doppler estimate into dop_hz, and the
       station's own bias is known here.                                  */
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
    /* The ground station needs the gap: it re-arms AFC/AGC after every frame
       and needs up to 60 ms to recover from a false start. At 80 ms the Pico
       ground station decoded 139 of 213; at 300 ms the Pi ground station
       stored 799 of 828 (2026-09-25), with the uplink Pico still on air. */
    delay(300);
  }
  f.close();
  digitalWrite(PIN_LED_B, LOW);
  /* Drop anything the transmit path left behind before listening again: the
     DIO0 line toggles during transmission, so without this the first loop
     after a downlink reads a phantom packet out of a FIFO that holds the tail
     of our own frame — seen on the bench as a record with a garbage callsign
     and a failed FCS. */
  radio.startReceive();
  rxFlag = false;
  Serial.printf("[dl] done: %lu/%lu sent\n", (unsigned long)sent, (unsigned long)total);
}

/* Park the receiver for the whole time COM_TX_ACTIVE is asserted. Called
   every loop() pass; only acts on an edge. The blanked time is counted, not
   written into the record store: a synthetic record would corrupt the dataset
   the ground platform scores, while a long gap_s on the next real packet plus
   these counters tell the analyst the silence was self-inflicted rather than
   a quiet channel.                                                          */
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

static void status() {
  File f = LittleFS.open(STORE, "r");
  uint32_t n = (f && f.size()) ? f.size() / sizeof(Record) : 0;
  if (f) f.close();

  // Table 7 rows 1-2. Averages are integer microseconds; with perf.n == 0
  // the four timing fields read 0 and mean "nothing measured yet".
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

/* ═══════════ radio supply monitor: INA219 ═════════════════════════════
   The radio's 3.3 V runs ESP32 3V3 -> INA219 VIN+ -> shunt -> VIN- -> Ra-01,
   so the shunt carries the radio's current and nothing else. Read over I2C
   by register, no library: shunt voltage LSB is 10 uV, so with the module's
   0.1 ohm shunt the current resolves to 0.1 mA — fine for Rx, standby and Tx,
   and too coarse for the SX1278's sub-microamp sleep, which reads as zero.
   Configured for a +-40 mV shunt range (+-400 mA) and 128-sample averaging
   (68 ms per conversion), continuous.                                     */
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

/* 'P': radio power profile. Listening, standby, sleep and a 2 dBm carrier
   (0.5 s, ISM band, the link's own power) in turn, then back to Rx.       */
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

/* Full receiver configuration, applied at boot and again whenever the radio
   is found back at its reset defaults (see radio_health()).              */
static int radio_config() {
  // 64-bit preamble, not the 16 the bench started with: AGC and AFC both
  // settle inside the preamble, and at -58 dBm 16 bits left too little clean
  // preamble behind them — the chip found the preamble but matched the sync
  // word on 3 packets out of 34. Same value on every node.
  int st = radio.beginFSK(CENTER_MHZ, 9.6, 5.0, 58.6, 2, 64);
  if (st != RADIOLIB_ERR_NONE) return st;
  radio.setCRC(true);
  // AFC. The FSK demodulator only locks on to carriers within about
  // +-freqDev of where it is tuned, and at 5 kHz that silently dropped every
  // source beyond ~+-5 kHz (GS100/GS109 and both off-frequency attackers).
  // Raising freqDev instead widened the window but made FEI useless: it
  // averages a few bits, so its error scales with freqDev (+-20 kHz at 40).
  // With AFC the chip measures the carrier in a wide AFC bandwidth at the
  // start of each reception and retunes to it before demodulating, so 5 kHz
  // keeps its FEI accuracy and the window grows to the AFC bandwidth.
  //  - AFC bandwidth 83.3 kHz (single-sided) covers the +28 kHz attacker plus
  //    the ~4 kHz two-crystal offset plus the 5 + 4.8 kHz signal itself.
  //  - AFC runs on the RSSI interrupt, not preamble detect: a carrier 30 kHz
  //    out cannot be demodulated, so its preamble is never detected until
  //    AFC has already pulled it in.
  //  - The RSSI threshold must sit above the noise floor, otherwise the RSSI
  //    interrupt fires on noise the moment RX starts and AFC locks onto
  //    nothing. RadioLib leaves it at -127.5 dBm; see rssiTrigDbm.
  //  - AfcAutoClearOn: each packet is measured from the nominal centre, not
  //    from the previous station's offset.
  radio.setAFCBandwidth(83.3);
  radio.setAFC(true);
  radio.setAFCAGCTrigger(RADIOLIB_SX127X_RX_TRIGGER_RSSI_INTERRUPT);
  radio.setRSSIThreshold(rssiTrigDbm);
  radioMod->SPIsetRegValue(RADIOLIB_SX127X_REG_AFC_FEI, RADIOLIB_SX127X_AFC_AUTO_CLEAR_ON, 0, 0);
  // 2-byte preamble detector, as on the Pi ground station (RadioLib's own
  // setting). One byte was chosen while the preamble was 16 bits; with 64 it
  // only fires on noise between frames. (A 2026-09-25 comparison that showed
  // 2 bytes losing every frame was taken while this receiver was stuck in
  // FS-Rx for an unrelated reason, so it is not evidence either way.)
  radioMod->SPIsetRegValue(RADIOLIB_SX127X_REG_PREAMBLE_DETECT,
      RADIOLIB_SX127X_PREAMBLE_DETECTOR_ON | RADIOLIB_SX127X_PREAMBLE_DETECTOR_2_BYTE |
      RADIOLIB_SX127X_PREAMBLE_DETECTOR_TOL);
  /* Keep CRC-failed frames in the FIFO (CrcAutoClearOff) and drop them in
     handle_uplink(), as the Pi ground station does: they are counted
     (crc_bad in 'S') instead of vanishing inside the chip, so a frame lost to
     bit errors is told apart from one that never synced.                   */
  radioMod->SPIsetRegValue(RADIOLIB_SX127X_REG_PACKET_CONFIG_1,
      RADIOLIB_SX127X_CRC_AUTOCLEAR_OFF, 3, 3);
  radio.setDio0Action(onRx, RISING);
  return radio.startReceive();
}

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
  // BRNG 16 V, PGA /1 (+-40 mV), 12-bit bus, 128-sample shunt, continuous
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
  // Median of 1 s of instantaneous RSSI with the receiver listening: the
  // floor, even if traffic is already on air (frames are ~6 % of the time).
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

/* AFC and AGC fire once, on the RSSI interrupt, and then hold. If that
   start does not end in a packet (noise over rssiTrigDbm, the tail of a
   frame, a preamble "detected" at the wrong AFC) the receiver keeps waiting
   for a sync word with the wrong frequency and gain, deaf to real traffic.
   Two guards, both leave Rx through startReceive(), which re-arms AFC/AGC:
    - RSSI start with no sync match after 60 ms. Not 20: the RSSI flag is
      sticky, so a 20 ms window restarted the receiver several times a second
      between frames and lost any frame that arrived during a restart (the
      ground station uses the same guard, gs_cti_pi.cpp). A frame is under
      60 ms on air, so 60 ms without sync is a genuine false start.
    - Sync match with no RxDone after 150 ms: a mistuned or clipped frame can
      leave the chip waiting for a payload that never completes (bench,
      2026-09-25: RSSI frozen at the last frame's level). Counted in
      rx_stuck ('S').                                                     */
static void rx_watchdog() {
  static uint32_t rssiSinceMs = 0, syncSinceMs = 0;
  if (rxBlanked) { rssiSinceMs = syncSinceMs = 0; return; }
  // Poll once a millisecond, as the Pi ground station does, not on every
  // loop pass: back-to-back register reads keep SPI clocking beside a
  // receiver that is trying to demodulate.
  static uint32_t lastPollUs = 0;
  if (micros() - lastPollUs < 1000) return;
  lastPollUs = micros();
  uint16_t irq = radio.getIRQFlags();
  uint8_t f1 = irq & 0xFF, f2 = irq >> 8;           // RegIrqFlags1 / 2
  // A completed packet whose DIO0 edge never reached onRx() is served from
  // the flag, as on the Pi ground station; counted in rx_polled ('S').
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

/* Two ways the receiver goes deaf without raising any flag the watchdog
   watches, both checked once a second:
    - A supply dip resets the SX1278 but not the ESP32: the chip comes back
      in standby at its reset defaults (bench, 2026-09-25: OpMode 0x09,
      RegBitrateMsb 0x1A). The configured bitrate reads 0x0D.
    - The chip keeps its configuration but has dropped to standby or sleep.
   Frequency-synthesis Rx (OpMode 0x0C) is NOT such a state: with the RSSI
   trigger the listening receiver sits there between frames and moves to Rx
   (0x0D) when a frame starts — the Pi ground station, decoding normally,
   read 0x0C in 2981 of 3000 samples.                                     */
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

/* 'Q': in-band scan. Steps the receiver across 433.40-433.60 MHz in 2 kHz
   steps and reports the mean and peak RSSI at each, so a spur near the
   channel (the node's own digital noise, a neighbour's LO) shows up as a
   peak. Run it with every transmitter silent. The receiver is reconfigured
   afterwards.                                                            */
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
