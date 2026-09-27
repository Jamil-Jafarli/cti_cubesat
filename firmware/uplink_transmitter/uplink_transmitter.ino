/* ═══════════════════════════════════════════════════════════════════════════
   Uplink transmitter — Raspberry Pi Pico + SX1278 (Dorji DRF1278F)

   Generates the uplink scenario the honeypot node is tested against. It plays
   five legitimate ground stations, each with its own callsign, carrier offset
   and command pattern, and after each of them sends one frame from a rotating
   list of attacks:

     UNK968 REBOOT              off frequency (+28 kHz), unknown source,
                                suspicious command
     GS104  ERASE_FLASH         the operator's own callsign from another radio
     UNK971 0x7F_UNKNOWN_OPCODE probing: unknown opcode, 0.9 s after the
                                previous frame, +24 kHz
     GS107  EPS_STATUS          Doppler spoof: correct callsign, bias and
                                command, but a fixed carrier (no Doppler tracking)
     GS102  HK_DUMP             malformed frame: everything correct except the
                                AX.25 FCS

   Frames are AX.25 UI frames SRC=<callsign> -> DST=HNY1 whose info field is
   "<seq>|<command>", sent as 2-FSK on 433.5 MHz (ISM band) at 2 dBm.

   The bench does not move, so the transmitter applies a simulated pass
   Doppler to its own carrier. Legitimate stations pre-compensate it, as a real
   ground station does; the attackers transmit on a fixed frequency.

   Hardware
     Raspberry Pi Pico, Dorji DRF1278F (SX1278)

   Wiring
     DRF1278F  SCK  -> GP18    MOSI -> GP19    MISO -> GP20    NSS -> GP17
               RESET -> GP22   DIO0 -> GP21    VCC  -> 3V3(OUT)  GND -> GND

   Build
     Board "Raspberry Pi Pico" (arduino-pico core), libraries RadioLib 7.7.1
     and HnyProto.

   Output (USB serial, 115200 baud): one "[up] ..." line per frame, read by
   analysis/benchlog.py and tools/uplink_monitor.
   ═══════════════════════════════════════════════════════════════════════════ */
#include <RadioLib.h>
#include <HnyProto.h>

/* ── pins and radio ───────────────────────────────────────────────────── */
#define PIN_SCK 18
#define PIN_MOSI 19
#define PIN_MISO 20   // any SPI0 RX-capable pin (GP0, GP4, GP16, GP20)
#define PIN_NSS 17
#define PIN_RST 22
#define PIN_DIO0 21
SX1278 radio = new Module(PIN_NSS, PIN_DIO0, PIN_RST, RADIOLIB_NC);

static const float CENTER_MHZ = 433.5f;

/* ── simulated pass Doppler ───────────────────────────────────────────────
   Straight-line flyby: r(t) = sqrt(d^2 + (v t)^2), range rate
   rdot = v^2 t / r, Doppler = -(rdot / c) f0, with t = 0 at closest approach.

   The amplitude is scaled for the bench, like the station offsets in
   HnyProto.h: a full-scale profile at 433.5 MHz peaks near 10.7 kHz, which on
   top of a +-8 kHz station offset would come close to the 20 kHz
   frequency-deviation threshold. A 6 kHz peak keeps the shape and the timing
   and leaves margin.                                                        */
static const float PASS_S      = 600.0f;      // 10-minute pass
static const float DOP_PEAK_HZ = 6000.0f;     // bench-scaled peak
static const float SAT_V_MS    = 7600.0f;     // LEO ground-relative speed
static const float SLANT_M     = 600000.0f;   // slant range at closest approach

static uint32_t passT0Ms = 0;

/* +DOP_PEAK_HZ at pass start (approaching), 0 at closest approach,
   -DOP_PEAK_HZ at pass end (receding).                                    */
static float doppler_hz(float t_s) {
  float t   = t_s - PASS_S * 0.5f;
  float vt  = SAT_V_MS * t;
  float rd  = (SAT_V_MS * SAT_V_MS * t) / sqrtf(SLANT_M * SLANT_M + vt * vt);
  float te  = PASS_S * 0.5f, vte = SAT_V_MS * te;
  float rdm = (SAT_V_MS * SAT_V_MS * te) / sqrtf(SLANT_M * SLANT_M + vte * vte);
  return -DOP_PEAK_HZ * (rd / rdm);
}

/* seconds into the current pass; passes repeat back to back */
static float pass_t_s() {
  return fmodf((float)(millis() - passT0Ms) / 1000.0f, PASS_S);
}

/* ── scenario ─────────────────────────────────────────────────────────── */
// command and interval of each legitimate station (callsigns and offsets are
// BENCH_GS in HnyProto.h)
struct GsBehaviour { const char *cmd; uint32_t gap_ms; };
static const GsBehaviour GS_TRAFFIC[N_BENCH_GS] = {
  {"TLM_REQ",      7000},   // GS100
  {"HK_DUMP",      9000},   // GS102
  {"PING",         5000},   // GS104
  {"EPS_STATUS",   8000},   // GS107
  {"PASS_SCHEDULE",11000},  // GS109
};

// Attack frames, sent one after each legitimate station. `dop` says whether
// the frame pre-compensates Doppler (an attacker without an orbit model does
// not), `corrupt` breaks the AX.25 FCS.
struct Attack { const char *src; const char *cmd; float freq_off_khz;
                uint32_t gap_ms; const char *what; bool dop; bool corrupt; };
static const Attack ATTACKS[] = {
  {"UNK968", "REBOOT",        28.0f, 4000, "freq+unknown+cmd", false, false},
  {"GS104",  "ERASE_FLASH",    0.0f, 4000, "callsign spoof",   false, false},
  {"UNK971", "0x7F_UNKNOWN_OPCODE", 24.0f, 900, "probing burst", false, false},
  // Doppler mismatch in isolation: a known callsign with its correct offset
  // and a benign command, so only the Doppler residual gives it away.
  {"GS107",  "EPS_STATUS",     4.0f, 5000, "doppler spoof",    false, false},
  // Malformed frame in isolation: everything correct except the AX.25 FCS,
  // so only the malformed-packet indicator fires.
  {"GS102",  "HK_DUMP",       -4.0f, 4000, "malformed FCS",    true,  true},
};
static const size_t N_ATT = sizeof(ATTACKS) / sizeof(ATTACKS[0]);

static uint32_t seq = 0;
static size_t attIdx = 0;

/* ── transmit one frame ───────────────────────────────────────────────── */
static void send_frame(const char *src, const char *cmd, float freq_off_khz,
                       bool pre_compensate, const char *what, bool corrupt_fcs) {
  float t   = pass_t_s();
  float dop = pre_compensate ? doppler_hz(t) : 0.0f;
  radio.setFrequency(CENTER_MHZ + freq_off_khz / 1000.0f + dop / 1.0e6f);
  char info[40];
  int ilen = snprintf(info, sizeof(info), "%lu|%s", (unsigned long)seq++, cmd);
  uint8_t frame[64];
  size_t n = ax25_build(frame, sizeof(frame), "HNY1", 0, src, 0,
                        (uint8_t *)info, ilen);
  // Only the AX.25 FCS is corrupted. The SX1278 adds its own PHY CRC over
  // whatever it is given, so the frame still reaches the honeypot with a
  // readable source and command. A corrupted payload would be discarded by
  // the receiver's PHY and never seen.
  if (corrupt_fcs && n >= 2) frame[n - 1] ^= 0x5A;
  int st = radio.transmit(frame, n);
  // heartbeat LED: the only sign of life when the Pico runs from a USB
  // charger without a serial console
  digitalWrite(LED_BUILTIN, HIGH); delay(30); digitalWrite(LED_BUILTIN, LOW);
  Serial.printf("[up] t=%5.1fs %-6s -> HNY1  %-20s foff=%+5.1f kHz  dop=%+6.0f Hz  %-16s %s%s\n",
                t, src, cmd, freq_off_khz, dop, what,
                corrupt_fcs ? "FCS-BROKEN " : "",
                st == RADIOLIB_ERR_NONE ? "sent" : "ERR");
  radio.setFrequency(CENTER_MHZ);
}

/* ── setup and loop ───────────────────────────────────────────────────── */
void setup() {
  Serial.begin(115200);
  delay(1500);
  pinMode(LED_BUILTIN, OUTPUT);
  SPI.setSCK(PIN_SCK); SPI.setTX(PIN_MOSI); SPI.setRX(PIN_MISO); SPI.begin();

  Serial.print("[up] SX1278 init ... ");
  // 2-FSK, 9.6 kb/s, 5 kHz deviation, 58.6 kHz RX bandwidth, 2 dBm, 64-bit
  // preamble: identical on every node of the bench
  int st = radio.beginFSK(CENTER_MHZ, 9.6, 5.0, 58.6, 2, 64);
  if (st != RADIOLIB_ERR_NONE) { Serial.printf("FAIL %d\n", st); while (1) delay(1000); }
  radio.setCRC(true);
  passT0Ms = millis();            // pass time starts with the first frame
  Serial.printf("ok — 5 ground stations + %u attack frames, %.0f s pass, "
                "Doppler +-%.0f Hz\n",
                (unsigned)N_ATT, PASS_S, DOP_PEAK_HZ);
}

void loop() {
  for (size_t i = 0; i < N_BENCH_GS; i++) {
    // legitimate station: pre-compensates Doppler, so its residual is ~0
    send_frame(BENCH_GS[i].call, GS_TRAFFIC[i].cmd, BENCH_GS[i].freq_off_khz,
               true, "legit", false);
    delay(GS_TRAFFIC[i].gap_ms);

    // one attack frame after each station; the list is walked round-robin
    // so every entry is used whatever its length
    const Attack &a = ATTACKS[attIdx++ % N_ATT];
    send_frame(a.src, a.cmd, a.freq_off_khz, a.dop, a.what, a.corrupt);
    delay(a.gap_ms);
  }
}
