/* ═══════════════════════════════════════════════════════════════════════
   PHASE 1 — uplink transmitter: Raspberry Pi Pico + SX1278

   Plays five legitimate ground stations plus an occasional attacker, sending
   AX.25 UI frames (real amateur-satellite framing) up to the honeypot node
   (hny_node_esp32). Each GS transmits from its own callsign with its own
   carrier offset, so the honeypot sees five distinct, recurring sources and
   the attacker traffic stands out.

   AX.25 UI frame: SRC=<GSxxx> -> DST=HNY1, info = "<seq>|<cmd>" (the command
   the station is sending). Sent over an SX1278 GFSK PHY on 433.5 MHz ISM.

   The downlink ground station is the Raspberry Pi (ground_station/gs_cti_pi).

   Library: RadioLib + HnyProto (libraries/HnyProto in this repository; pass it with --library or copy it to
   ~/Arduino/libraries). Board: Raspberry Pi Pico (arduino-pico core).
   ═══════════════════════════════════════════════════════════════════════ */
#include <RadioLib.h>
#include <HnyProto.h>

#define PIN_SCK 18
#define PIN_MOSI 19
#define PIN_MISO 20   // SPI0 RX; moved from GP16 after its pad failed twice (2026-09-25)
#define PIN_NSS 17
#define PIN_RST 22    // any GPIO; moved off GP20 to free it for MISO
#define PIN_DIO0 21
SX1278 radio = new Module(PIN_NSS, PIN_DIO0, PIN_RST, RADIOLIB_NC);

static const float CENTER_MHZ = 433.5f;

/* ── pass profile (paper 5, 6.4) ─────────────────────────────────────────
   Straight-line flyby: r(t) = sqrt(d^2 + (v t)^2), range rate
   rdot = v^2 t / r, Doppler = -(rdot/c) f0, with t = 0 at closest approach.
   The bench does not move, so the TRANSMITTER applies the shift itself and
   the honeypot's FEI register sees exactly what a real pass produces.

   The amplitude is BENCH-SCALED, like the station biases in HnyProto.h: at
   433.5 MHz the full-scale profile peaks near 10.7 kHz, which on top of a
   +-8 kHz station bias lands at 18.7 kHz — just under the 20 kHz frequency-
   deviation threshold, so FEI noise would trip that indicator on legitimate
   traffic. 6 kHz keeps the shape and the timing and leaves margin.

   Legitimate stations pre-compensate (they follow the profile). Attackers
   transmit on a fixed frequency, which is what a ground attacker without an
   orbit model actually does — so their Doppler residual is the full expected
   profile, and the ground platform sees it.                              */
static const float PASS_S      = 600.0f;      // 10-minute pass
static const float DOP_PEAK_HZ = 6000.0f;     // bench-scaled peak
static const float SAT_V_MS    = 7600.0f;     // LEO ground-relative speed
static const float SLANT_M     = 600000.0f;   // slant range at closest approach

static uint32_t passT0Ms = 0;

/* +DOP_PEAK_HZ at pass start (approaching) -> 0 at closest approach ->
   -DOP_PEAK_HZ at pass end (receding).                                  */
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

// how each legit GS behaves: which commands, how often
struct GsBehaviour { const char *cmd; uint32_t gap_ms; };
static const GsBehaviour GS_TRAFFIC[N_BENCH_GS] = {
  {"TLM_REQ",      7000},   // GS100
  {"HK_DUMP",      9000},   // GS102
  {"PING",         5000},   // GS104
  {"EPS_STATUS",   8000},   // GS107
  {"PASS_SCHEDULE",11000},  // GS109
};

// Attacker frames injected between the legit stations. `dop` says whether the
// frame pre-compensates Doppler; an attacker without an orbit model does not,
// which is why most of these are false. `corrupt` breaks the AX.25 FCS.
struct Attack { const char *src; const char *cmd; float freq_off_khz;
                uint32_t gap_ms; const char *what; bool dop; bool corrupt; };
static const Attack ATTACKS[] = {
  {"UNK968", "REBOOT",        28.0f, 4000, "freq+unknown+cmd", false, false},
  {"GS104",  "ERASE_FLASH",    0.0f, 4000, "callsign spoof",   false, false},
  {"UNK971", "0x7F_UNKNOWN_OPCODE", 24.0f, 900, "probing burst", false, false},
  // Doppler mismatch, isolated: a known callsign with its correct bias and a
  // benign command — nothing else fires, so only the Doppler residual gives
  // it away. This is the spoofer the paper's RF fingerprinting is aimed at.
  {"GS107",  "EPS_STATUS",     4.0f, 5000, "doppler spoof",    false, false},
  // Malformed packet, isolated: everything correct — known callsign, its own
  // bias, a benign command, Doppler tracked, normal timing — except the AX.25
  // FCS, so only the malformed-packet indicator fires (+10).
  {"GS102",  "HK_DUMP",       -4.0f, 4000, "malformed FCS",    true,  true},
};
static const size_t N_ATT = sizeof(ATTACKS) / sizeof(ATTACKS[0]);

static uint32_t seq = 0;
static size_t attIdx = 0;

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
  // Corrupt the AX.25 FCS only, leaving the addresses and the info field
  // intact: the SX1278 computes its own PHY CRC over whatever we hand it, so
  // the frame still reaches the honeypot's FIFO and the record carries a
  // readable source and command with crc_ok = 0. Corrupting the payload
  // instead would be discarded by the PHY and never seen at all.
  if (corrupt_fcs && n >= 2) frame[n - 1] ^= 0x5A;
  int st = radio.transmit(frame, n);
  // Heartbeat: the bench often runs the Pico from a power-only USB cable,
  // where the CDC serial log goes nowhere — this LED is the only sign the
  // transmitter is alive. 30 ms against 4-11 s inter-frame gaps.
  digitalWrite(LED_BUILTIN, HIGH); delay(30); digitalWrite(LED_BUILTIN, LOW);
  Serial.printf("[up] t=%5.1fs %-6s -> HNY1  %-20s foff=%+5.1f kHz  dop=%+6.0f Hz  %-16s %s%s\n",
                t, src, cmd, freq_off_khz, dop, what,
                corrupt_fcs ? "FCS-BROKEN " : "",
                st == RADIOLIB_ERR_NONE ? "sent" : "ERR");
  radio.setFrequency(CENTER_MHZ);
}

void setup() {
  Serial.begin(115200);
  delay(1500);
  pinMode(LED_BUILTIN, OUTPUT);
  SPI.setSCK(PIN_SCK); SPI.setTX(PIN_MOSI); SPI.setRX(PIN_MISO); SPI.begin();

  Serial.print("[up] SX1278 init ... ");
  // 64-bit preamble, not the 16 the bench started with: AGC and AFC both
  // settle inside the preamble, and at -58 dBm 16 bits left too little clean
  // preamble behind them — the chip found the preamble but matched the sync
  // word on 3 packets out of 34. Same value on every node.
  int st = radio.beginFSK(CENTER_MHZ, 9.6, 5.0, 58.6, 2, 64);
  if (st != RADIOLIB_ERR_NONE) { Serial.printf("FAIL %d\n", st); while (1) delay(1000); }
  radio.setCRC(true);
  passT0Ms = millis();            // pass time starts with the first frame
  Serial.printf("ok — 5 ground stations + %u attack frames, %.0f s pass, "
                "Doppler +-%.0f Hz\n",
                (unsigned)N_ATT, PASS_S, DOP_PEAK_HZ);
}

void loop() {
  // one legit pass from each of the five stations
  for (size_t i = 0; i < N_BENCH_GS; i++) {
    // legit stations pre-compensate Doppler, so their residual is ~0
    send_frame(BENCH_GS[i].call, GS_TRAFFIC[i].cmd, BENCH_GS[i].freq_off_khz,
               true, "legit", false);
    delay(GS_TRAFFIC[i].gap_ms);

    // one attacker frame after each legit station. The table is walked
    // round-robin so every entry is exercised even when it is longer or
    // shorter than the station list.
    const Attack &a = ATTACKS[attIdx++ % N_ATT];
    send_frame(a.src, a.cmd, a.freq_off_khz, a.dop, a.what, a.corrupt);
    delay(a.gap_ms);
  }
}
