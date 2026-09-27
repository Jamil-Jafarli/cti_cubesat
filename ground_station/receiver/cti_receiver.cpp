/* ═══════════════════════════════════════════════════════════════════════
   CTI receiver — Raspberry Pi 4 + Ai-Thinker Ra-01 (SX1278)

   Receives the honeypot's downlink: AX.25 UI frames HNY1 -> CTIGS, one per
   CTI record the honeypot stored in its flash. The info field of every valid
   frame is a packed RecordWire (HnyProto.h); it is expanded here into the CSV
   line the server parses and written to stdout as

       CTI,<csv>

   hny_server.py --radio starts this program and reads its stdout, so the
   server and the radio run on the same machine. Everything else on stdout is
   a "[gs] ..." log line that the server echoes. Frames that are not part of
   the downlink (for example the uplink the honeypot hears) are logged in
   full, which makes this receiver a reference for link tests.

   Same radio stack as the microcontroller nodes: RadioLib 7.7.1 through its
   Raspberry Pi HAL (lgpio), and HnyProto.h for the framing and the record
   format, so neither exists twice.

   Usage: cti_receiver [--rssi-threshold DBM]

   Wiring (BCM numbering, see README.md):
     SCK  -> GPIO11 (SPI0 SCLK)     MISO -> GPIO9 (SPI0 MISO)
     MOSI -> GPIO10 (SPI0 MOSI)     NSS  -> GPIO8 (SPI0 CE0, driven by the kernel)
     RESET -> GPIO25                DIO0 -> GPIO24
     3.3V -> 3V3                    GND  -> GND
   ═══════════════════════════════════════════════════════════════════════ */
#include <RadioLib.h>
#include "hal/RPi/PiHal.h"
#include <HnyProto.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/prctl.h>

static const int PIN_RST  = 25;
static const int PIN_DIO0 = 24;
static const float CENTER_MHZ = 433.5f;

/* The kernel's spidev driver asserts CE0 for exactly one transfer, and
   RadioLib sends every register access as one transfer (Module::SPItransfer),
   so NSS is left to the kernel and RadioLib gets RADIOLIB_NC for it.       */
static PiHal *hal = new PiHal(0, 2000000);
static Module *radioMod = new Module(hal, RADIOLIB_NC, PIN_DIO0, PIN_RST, RADIOLIB_NC);
static SX1278 radio = radioMod;

/* RSSI level that starts an AFC/AGC cycle. It has to sit above the noise
   floor and below the downlink, and a fixed value does not survive moving
   the boards. By default the floor is measured at start and the threshold
   set RSSI_MARGIN_DB above it; --rssi-threshold fixes it instead.          */
static const float RSSI_MARGIN_DB = 15.0f;
static float rssiThresholdDbm = NAN;          // NAN: measure at start

static std::atomic<bool> rxFlag{false};
static void onRx() { rxFlag = true; }

static volatile sig_atomic_t stopRequested = 0;
static void onSignal(int) { stopRequested = 1; }

// counters for the periodic "[gs] alive" line and the exit summary
static unsigned long nRx = 0, nCti = 0, nIgnored = 0, nDropped = 0;
static unsigned long nRestarts = 0, nStuck = 0, nReinit = 0;
static float rssiMin = 0.0f, rssiMax = -200.0f;   // since the last alive line

/* Median of 1 s of instantaneous RSSI with the receiver listening. The
   downlink occupies ~20 % of the air when it runs (60 ms frames 300 ms
   apart), so the median is the floor even if a pass is already underway. */
static float measure_floor_dbm() {
  static float v[200];
  int n = 0;
  for (; n < 200; n++) { v[n] = radio.getRSSI(false, true); hal->delay(5); }
  std::sort(v, v + n);
  return v[n / 2];
}

/* Whole receiver configuration, run at start and again whenever the chip is
   found back at its reset defaults (radio_health).                         */
static int radio_config() {
  // 64-bit preamble on every node: AGC and AFC both settle inside it.
  int st = radio.beginFSK(CENTER_MHZ, 9.6, 5.0, 58.6, 2, 64);
  if (st != RADIOLIB_ERR_NONE) return st;
  radio.setCRC(true);
  // AFC: the demodulator only locks within about +-freqDev (5 kHz) of where
  // it is tuned and the two crystals alone are a few kHz apart. AFC retunes
  // to the carrier at the start of each reception.
  radio.setAFCBandwidth(83.3);
  radio.setAFC(true);
  radio.setAFCAGCTrigger(RADIOLIB_SX127X_RX_TRIGGER_RSSI_INTERRUPT);
  radio.setRSSIThreshold(std::isnan(rssiThresholdDbm) ? -70.0f : rssiThresholdDbm);
  // Measure every packet from the channel centre, not from the previous
  // correction: otherwise an AFC cycle started by noise leaves the receiver
  // retuned and later frames fail to match their sync word.
  radioMod->SPIsetRegValue(RADIOLIB_SX127X_REG_AFC_FEI,
                           RADIOLIB_SX127X_AFC_AUTO_CLEAR_ON, 0, 0);
  // Keep CRC-failed frames: they raise PayloadReady and are counted as
  // dropped in handle_downlink(), so a record lost on the air is told apart
  // from one that never synced at all.
  radioMod->SPIsetRegValue(RADIOLIB_SX127X_REG_PACKET_CONFIG_1,
                           RADIOLIB_SX127X_CRC_AUTOCLEAR_OFF, 3, 3);
  radio.setDio0Action(onRx, hal->GpioInterruptRising);
  return radio.startReceive();
}

/* AFC and AGC fire once, on the RSSI interrupt, and then hold; a start that
   does not end in a packet leaves the receiver retuned and deaf. Two guards,
   both leaving Rx through startReceive(), which re-arms AFC/AGC:
    - RSSI start with no sync match after 60 ms. The RSSI flag is sticky, so
      a shorter window restarts the receiver between frames and loses any
      frame that arrives during the restart. A frame is ~50 ms on air.
    - Sync match with no packet after 150 ms: a clipped or mistuned frame can
      leave the chip waiting for a payload that never completes.
   PayloadReady is also checked here, so a packet whose DIO0 edge was missed
   is still served.                                                       */
static void rx_watchdog() {
  static unsigned long rssiSinceMs = 0, syncSinceMs = 0;
  uint16_t irq = radio.getIRQFlags();
  uint8_t f1 = irq & 0xFF, f2 = irq >> 8;
  if ((f2 & RADIOLIB_SX127X_FLAG_PAYLOAD_READY) && !rxFlag) { rxFlag = true; return; }
  bool rssi = f1 & RADIOLIB_SX127X_FLAG_RSSI;
  bool sync = f1 & RADIOLIB_SX127X_FLAG_SYNC_ADDRESS_MATCH;
  unsigned long now = hal->millis();
  if (sync) {
    rssiSinceMs = 0;
    if (!syncSinceMs) { syncSinceMs = now | 1; return; }
    if (now - syncSinceMs >= 150) { syncSinceMs = 0; nStuck++; radio.startReceive(); }
    return;
  }
  syncSinceMs = 0;
  if (!rssi) { rssiSinceMs = 0; return; }
  if (!rssiSinceMs) { rssiSinceMs = now | 1; return; }
  if (now - rssiSinceMs >= 60) { rssiSinceMs = 0; nRestarts++; radio.startReceive(); }
}

/* A supply dip resets the SX1278 without resetting this program; the chip
   comes back in standby at its reset defaults and the receiver is silently
   deaf. The configured bitrate (9.6 kb/s) reads 0x0D in RegBitrateMsb.     */
static void radio_health() {
  static unsigned long lastMs = 0;
  unsigned long now = hal->millis();
  if (now - lastMs < 1000) return;
  lastMs = now;
  if (radioMod->SPIgetRegValue(RADIOLIB_SX127X_REG_BITRATE_MSB) == 0x0D) return;
  nReinit++;
  int st = radio_config();
  printf("[gs] radio lost its configuration, reconfigured (st=%d)\n", st);
}

/* Carrier offset the AFC applied to the frame just received, in kHz
   (RegAfcValue, signed, Fstep = 32 MHz / 2^19), as the honeypot reads it. */
static float afc_khz() {
  int16_t afc = (int16_t)((radioMod->SPIreadRegister(RADIOLIB_SX127X_REG_AFC_MSB) << 8) |
                           radioMod->SPIreadRegister(RADIOLIB_SX127X_REG_AFC_LSB));
  return afc * (32000000.0f / 524288.0f) / 1000.0f;
}

static void handle_downlink() {
  uint8_t buf[256];
  nRx++;
  float rssi = radio.getRSSI(false, true);
  float afc = afc_khz();
  int len = (int)radio.getPacketLength();
  // RadioLib checks the CRC only in LoRa mode; in FSK it has to be read from
  // RegIrqFlags2 before readData() clears the flags.
  bool crcOk = (radio.getIRQFlags() >> 8) & RADIOLIB_SX127X_FLAG_CRC_OK;
  int st = radio.readData(buf, len > 0 && len < (int)sizeof(buf) ? len : sizeof(buf));
  radio.startReceive();
  if (!crcOk) {
    nDropped++;
    printf("[gs] frame dropped: PHY CRC failed, len=%d rssi=%.0f afc=%+.1f\n", len, rssi, afc);
    return;
  }
  if (st != RADIOLIB_ERR_NONE || len <= 0) {
    nDropped++;
    printf("[gs] frame dropped: st=%d len=%d rssi=%.0f\n", st, len, rssi);
    return;
  }

  char src[10] = {0}, dst[10] = {0}, info[180] = {0};
  size_t ilen = 0;
  if (!ax25_parse(buf, (size_t)len, src, sizeof(src), dst, sizeof(dst),
                  (uint8_t *)info, sizeof(info), &ilen)) {
    nDropped++;
    printf("[gs] frame dropped: AX.25 FCS failed, len=%d rssi=%.0f\n", len, rssi);
    return;
  }
  if (strcmp(dst, "CTIGS") || strcmp(src, "HNY1")) {
    // Not ours, but logged in full: the uplink the honeypot hears is also
    // heard here, which makes this receiver a reference for link tests.
    nIgnored++;
    char txt[40];
    size_t k = 0;
    for (; k < ilen && k < sizeof(txt) - 1; k++)
      txt[k] = (info[k] >= 32 && info[k] < 127) ? info[k] : '.';
    txt[k] = 0;
    printf("[gs] ignoring frame %s -> %s rssi=%.0f afc=%+.1f info=%s (not the HNY downlink)\n",
           src, dst, rssi, afc, txt);
    return;
  }
  if (ilen != sizeof(RecordWire)) {
    nDropped++;
    printf("[gs] unexpected record size %zu (want %zu)\n", ilen, sizeof(RecordWire));
    return;
  }
  RecordWire w;
  memcpy(&w, info, sizeof(w));
  char csv[200];
  wire_to_csv(w, csv, sizeof(csv));
  nCti++;
  printf("CTI,%s\n", csv);
}

static void print_counters(const char *tag) {
  printf("[gs] %s rx=%lu cti=%lu dropped=%lu ignored=%lu restarts=%lu stuck=%lu "
         "reinit=%lu rssi_min=%.0f rssi_max=%.0f\n",
         tag, nRx, nCti, nDropped, nIgnored, nRestarts, nStuck, nReinit,
         rssiMin, rssiMax);
  rssiMin = 0.0f; rssiMax = -200.0f;
}

/* Instantaneous RSSI every 10 ms, for the alive line: the minimum is the
   noise floor, the maximum the strongest frame heard in the period.       */
static void sample_rssi() {
  static unsigned long lastMs = 0;
  unsigned long now = hal->millis();
  if (now - lastMs < 10) return;
  lastMs = now;
  float r = radio.getRSSI(false, true);
  if (r < rssiMin) rssiMin = r;
  if (r > rssiMax) rssiMax = r;
}

int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--rssi-threshold") && i + 1 < argc) {
      rssiThresholdDbm = strtof(argv[++i], nullptr);
    } else {
      fprintf(stderr, "usage: %s [--rssi-threshold DBM]   (default: noise floor + %.0f dB)\n",
              argv[0], RSSI_MARGIN_DB);
      return 2;
    }
  }
  setvbuf(stdout, nullptr, _IOLBF, 0);   // one line at a time to the server
  signal(SIGINT, onSignal);
  signal(SIGTERM, onSignal);
  // Exit with the server that started us: an orphaned receiver keeps SPI and
  // the GPIO lines, and the next one then shares the radio with it.
  prctl(PR_SET_PDEATHSIG, SIGTERM);

  int st = radio_config();
  /* Keep retrying instead of exiting: a module that is still being wired or
     whose supply contact is open must not take the ground station down.  */
  while (st != RADIOLIB_ERR_NONE && !stopRequested) {
    printf("[gs] radio init FAILED, code %d; check the module's wiring and 3.3 V, "
           "retrying\n", st);
    for (int i = 0; i < 20 && !stopRequested; i++) hal->delay(100);
    st = radio_config();
  }
  if (stopRequested) return 1;
  float floorDbm = measure_floor_dbm();
  if (std::isnan(rssiThresholdDbm)) {
    rssiThresholdDbm = std::min(-60.0f, std::max(-100.0f, floorDbm + RSSI_MARGIN_DB));
    radio.setRSSIThreshold(rssiThresholdDbm);   // kept by radio_config() from here on
    radio.startReceive();
  }
  printf("[gs] ok — listening for HNY1 downlink (CTIGS) on %.1f MHz, noise floor "
         "%.1f dBm, RSSI threshold %.1f dBm\n", CENTER_MHZ, floorDbm, rssiThresholdDbm);

  unsigned long aliveMs = hal->millis();
  while (!stopRequested) {
    if (rxFlag.exchange(false)) handle_downlink();
    rx_watchdog();
    radio_health();
    sample_rssi();
    if (hal->millis() - aliveMs >= 60000) { aliveMs = hal->millis(); print_counters("alive"); }
    hal->delay(1);
  }
  radio.standby();
  print_counters("stopped");
  hal->term();
  return 0;
}
