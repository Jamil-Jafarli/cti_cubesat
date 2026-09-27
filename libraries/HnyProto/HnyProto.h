/* ═══════════════════════════════════════════════════════════════════════
   HnyProto — shared protocol and detection code for the honeypot CubeSat bench

   A header-only Arduino library used by every node (firmware/honeypot_node,
   firmware/uplink_transmitter, firmware/link_test and the Raspberry Pi
   receiver in ground_station/receiver), so the RF wire format and the
   detection math are defined once.

   Install: pass this folder to arduino-cli with --library, or copy it to
   ~/Arduino/libraries/HnyProto.

   Contents
     · AX.25 UI frame encode/decode with the AX.25 CRC-16/X.25 FCS, carried
       over the SX1278's 2-FSK packet engine;
     · the bench ground-station table and the 16-entry fuzzy registry;
     · transmitter signatures, the fingerprint whitelist and the member-mode
       verdict;
     · the seven-indicator anomaly score and the fuzzy transmitter match
       (the same math as simulation/detector.py; the SHA-256 record
       fingerprint is added by the honeypot sketch);
     · the fixed-size CTI Record, its CSV form and the packed downlink record.

   The constants are kept in sync by hand with simulation/profiles.py and
   simulation/detector.py.
   ═══════════════════════════════════════════════════════════════════════ */
#pragma once
#include <Arduino.h>
#include <string.h>
#include <math.h>

/* ══════════════════════ AX.25 UI framing ══════════════════════════════ */
/* CRC-16/X.25: poly 0x1021 reflected (0x8408), init 0xFFFF, xorout 0xFFFF.  */
static inline uint16_t ax25_fcs(const uint8_t *d, size_t n) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= d[i];
    for (int b = 0; b < 8; b++)
      crc = (crc & 1) ? (crc >> 1) ^ 0x8408 : (crc >> 1);
  }
  return ~crc;
}

/* write a 7-byte AX.25 address: 6 callsign chars <<1, then SSID byte.
   last=true sets bit0 of the SSID byte (end of address field).            */
static inline void ax25_addr(uint8_t *o, const char *call, uint8_t ssid, bool last) {
  for (int i = 0; i < 6; i++) {
    char c = (i < (int)strlen(call)) ? call[i] : ' ';
    o[i] = (uint8_t)c << 1;
  }
  o[6] = 0x60 | ((ssid & 0x0F) << 1) | (last ? 0x01 : 0x00);
}

/* build a UI frame (control 0x03, PID 0xF0). Returns total length or 0.     */
static inline size_t ax25_build(uint8_t *out, size_t cap,
                                const char *dst, uint8_t dssid,
                                const char *src, uint8_t sssid,
                                const uint8_t *info, size_t ilen) {
  if (cap < 16 + ilen + 2) return 0;
  size_t n = 0;
  ax25_addr(out + n, dst, dssid, false); n += 7;
  ax25_addr(out + n, src, sssid, true);  n += 7;
  out[n++] = 0x03;                       // UI control
  out[n++] = 0xF0;                       // PID: no layer 3
  memcpy(out + n, info, ilen); n += ilen;
  uint16_t fcs = ax25_fcs(out, n);
  out[n++] = fcs & 0xFF;                 // FCS low byte first
  out[n++] = (fcs >> 8) & 0xFF;
  return n;
}

/* decode + verify a UI frame. Fills src callsign ("GS104") and info.

   fcs_ok == nullptr (the default) is strict: a frame whose FCS does not check
   out is rejected. That is what the CTI ground station wants — a corrupted
   downlink record would poison the database.

   Pass an fcs_ok pointer and the frame is decoded even with a bad FCS, with
   validity reported instead of thrown away. That is what the honeypot wants:
   it logs every received packet regardless of validity, and the
   malformed-packet indicator needs the record to exist.
   The address and info fields are still read — a damaged FCS says nothing
   about the bytes before it — so the record keeps its source and command.  */
static inline bool ax25_parse(const uint8_t *f, size_t n,
                              char *src_out, size_t src_cap,
                              char *dst_out, size_t dst_cap,
                              uint8_t *info_out, size_t info_cap, size_t *ilen,
                              bool *fcs_ok = nullptr) {
  if (n < 18) return false;
  uint16_t fcs = ax25_fcs(f, n - 2);
  bool ok = ((f[n - 2] | (f[n - 1] << 8)) == fcs);
  if (fcs_ok) *fcs_ok = ok;
  else if (!ok) return false;
  auto call = [](const uint8_t *a, char *o, size_t cap) {
    size_t k = 0;
    for (int i = 0; i < 6 && k + 1 < cap; i++) {
      char c = (char)(a[i] >> 1);
      if (c != ' ') o[k++] = c;
    }
    o[k] = 0;
  };
  if (dst_out) call(f + 0, dst_out, dst_cap);
  if (src_out) call(f + 7, src_out, src_cap);
  size_t li = n - 16 - 2;
  if (li > info_cap - 1) li = info_cap - 1;
  memcpy(info_out, f + 16, li);
  info_out[li] = 0;
  if (ilen) *ilen = li;
  return true;
}

/* ══════════════════════ bench ground stations ════════════════════════ */
/* Callsigns carry no dash (AX.25 uses the dash for the SSID). freq_off_khz
   is scaled for the bench (±8 kHz) so the five stations are separable well
   above the measurement error; the registry below uses the sub-kHz residuals
   of simulation/profiles.py.                                                */
struct BenchGs { const char *call; float freq_off_khz; float drift_ppm; };
static const BenchGs BENCH_GS[] = {
  {"GS100", -8.0f, 0.04f},
  {"GS102", -4.0f, 0.06f},
  {"GS104",  0.0f, 0.03f},
  {"GS107",  4.0f, 0.05f},
  {"GS109",  8.0f, 0.02f},
};
static const size_t N_BENCH_GS = sizeof(BENCH_GS) / sizeof(BENCH_GS[0]);

/* full 16-entry fuzzy registry (sub-kHz carrier residuals, drift in ppm) */
struct GsProfile { const char *id; float bias_khz; float drift_ppm; };
static const GsProfile REGISTRY[] = {
  {"GS100",  0.64f, 0.04f}, {"GS101", -0.82f, 0.11f},
  {"GS102",  0.41f, 0.06f}, {"GS103", -0.52f, 0.09f},
  {"GS104",  0.88f, 0.03f}, {"GS105", -0.23f, 0.07f},
  {"GS106",  0.19f, 0.12f}, {"GS107", -0.71f, 0.05f},
  {"GS108",  0.29f, 0.08f}, {"GS109",  0.81f, 0.02f},
  {"GS110", -0.35f, 0.10f}, {"GS111",  0.51f, 0.06f},
  {"GS112", -0.93f, 0.04f}, {"GS113",  0.12f, 0.09f},
  {"GS114", -0.59f, 0.11f}, {"GS115",  0.76f, 0.05f},
};
static const size_t N_GS = sizeof(REGISTRY) / sizeof(REGISTRY[0]);

/* ═════════════ transmitter signature + fingerprint whitelist ══════════
   The `fp` field is a SHA-256 over the packet's own fields, so it is a record
   identifier and changes with every frame; nothing can be whitelisted on it. What does survive from packet to packet is the physical
   layer the transmitter cannot easily change: the carrier offset its
   oscillator lands on. Quantised into half-kHz buckets and paired with the
   claimed callsign, that is a usable identity:

       GS104@+0.0     the operator's own station, as enrolled
       GS104@+24.5    somebody else transmitting GS104's callsign

   The whitelist is an ALLOWLIST OF SIGNATURES, not of callsigns. That is the
   difference that matters: a callsign-only allowlist hands an attacker the
   override simply for spelling the right six characters, which is exactly the
   ERASE_FLASH spoof on this bench. Binding the callsign to the RF signature
   means the spoofer fails the check while the real station passes it.

   Tolerance is per entry because a station's offset drifts with temperature
   and ages; the enrolment tolerance is wide enough for that and far tighter
   than the ±8 kHz the bench stations are separated by.                    */
static const float FP_BUCKET_KHZ = 0.5f;

static inline void hny_signature(const char *src, float dev_khz,
                                 char *out, size_t cap) {
  float q = roundf(dev_khz / FP_BUCKET_KHZ) * FP_BUCKET_KHZ;
  if (q == 0.0f) q = 0.0f;                       // avoid "-0.0"
  snprintf(out, cap, "%s@%+.1f", src, q);
}

enum WlState : uint8_t { WL_NONE = 0, WL_MATCH = 1, WL_MISMATCH = 2 };

struct FpAllow {
  char     call[10];
  float    bias_khz;        // enrolled carrier offset
  float    tol_khz;         // how far it may wander and still be the same radio
  uint8_t  conf;            // how much the enrolment is trusted, 0-100
  uint32_t hits;            // frames matched since enrolment
};

/* WL_NONE  — nothing enrolled for this callsign, so the whitelist has no
               opinion and the caller must fall back to its other rules.
   WL_MATCH — callsign and signature both match an enrolled entry.
   WL_MISMATCH — the callsign is enrolled but arrived on the wrong carrier:
               someone is using it who is not the enrolled transmitter.    */
static inline WlState fp_allow_check(const FpAllow *tbl, size_t n,
                                     const char *src, float dev_khz,
                                     const FpAllow **hit = nullptr) {
  if (hit) *hit = nullptr;
  bool call_known = false;
  for (size_t i = 0; i < n; i++) {
    if (strcmp(src, tbl[i].call)) continue;
    call_known = true;
    if (fabsf(dev_khz - tbl[i].bias_khz) <= tbl[i].tol_khz) {
      if (hit) *hit = &tbl[i];
      return WL_MATCH;
    }
  }
  return call_known ? WL_MISMATCH : WL_NONE;
}

/* Carrier offset a bench station is known to transmit on. Returns false for a
   callsign the bench does not run, whose offset therefore carries no
   information about the pass.                                              */
static inline bool bench_bias_khz(const char *call, float *bias) {
  for (size_t i = 0; i < N_BENCH_GS; i++) {
    if (strcmp(call, BENCH_GS[i].call)) continue;
    if (bias) *bias = BENCH_GS[i].freq_off_khz;
    return true;
  }
  return false;
}

/* ══════════════════════ member mode ══════════════════════════════════
   On a member satellite the board is a gate, not a sensor: the on-board
   computer asks for a verdict before executing an uplink command. Two lists
   decide it.

   The ALLOWLIST is the satellite's own ground stations and always wins. It is
   the defence against "blaming someone else": an attacker who imitates a
   legitimate station could otherwise get that station blocklisted and lock
   the operator out of their own satellite.

   The BLOCKLIST comes from the ground platform and stores transmitter
   signatures, not record hashes: a SHA-256 changes completely when the
   frequency moves by 10 Hz, and Doppler differs for every pass, so the
   comparison is fuzzy (callsign plus carrier offset within a tolerance).

   Matching on the raw offset works on the bench because attackers do not
   pre-compensate Doppler, so their carrier stays put while a legitimate
   station's moves with the pass. Only entries at or above BLOCK_CONF_MIN are
   acted on.                                                                */
struct AllowEntry { const char *call; };
static const AllowEntry ALLOWLIST[] = {
  {"GS104"},                  // this satellite's own operator
};
static const size_t N_ALLOW = sizeof(ALLOWLIST) / sizeof(ALLOWLIST[0]);

struct BlockEntry { const char *call; float bias_khz; float tol_khz; float conf; };
static const BlockEntry BLOCKLIST[] = {
  {"UNK968", 28.0f, 2.0f, 91.0f},   // seen flooding REBOOT off-frequency
  {"UNK971", 24.0f, 2.0f, 88.0f},   // probing burst, unknown opcode
  // Deliberately also lists the operator's own station, which an attacker
  // spoofed (the ERASE_FLASH frames). The allowlist must override this, and
  // the bench shows it doing so.
  {"GS104",   0.0f, 2.0f, 85.0f},
};
static const size_t N_BLOCK = sizeof(BLOCKLIST) / sizeof(BLOCKLIST[0]);

static const float BLOCK_CONF_MIN = 80.0f;

enum Verdict : uint8_t { V_ACCEPT = 0, V_BLOCK = 1, V_ALLOW_OVERRIDE = 2,
                         V_SPOOF_SUSPECT = 3 };

/* Verdict for one uplink packet, with the fingerprint whitelist consulted for
   the allowlist override. Fail-open by design: anything this function cannot
   positively match is accepted, so a false positive can never make the
   satellite uncommandable.                                                 */
static inline Verdict hny_verdict_fp(const char *src, float freq_dev_khz,
                                     float resid_khz,
                                     const FpAllow *wl, size_t n_wl,
                                     const BlockEntry **hit, WlState *wl_out) {
  if (hit) *hit = nullptr;
  const BlockEntry *m = nullptr;
  for (size_t i = 0; i < N_BLOCK; i++) {
    if (strcmp(src, BLOCKLIST[i].call)) continue;
    if (fabsf(freq_dev_khz - BLOCKLIST[i].bias_khz) > BLOCKLIST[i].tol_khz) continue;
    if (BLOCKLIST[i].conf < BLOCK_CONF_MIN) continue;
    m = &BLOCKLIST[i];
    break;
  }
  if (hit) *hit = m;

  /* The two lists are matched on different quantities on purpose. Blocklist
     entries are raw carrier offsets: an attacker transmits on a fixed
     frequency, so that is where it stays. Whitelist entries are RESIDUALS —
     the offset left after the pass Doppler is removed — because a legitimate
     station pre-compensates and its raw carrier sweeps across several kHz by
     design. Matching a whitelist on the raw offset would flag the real
     station every time the pass moved it. */
  WlState w = fp_allow_check(wl, n_wl, src, resid_khz);
  if (wl_out) *wl_out = w;

  for (size_t i = 0; i < N_ALLOW; i++) {
    if (strcmp(src, ALLOWLIST[i].call)) continue;
    /* The callsign is one of ours. Whether it gets the override now depends on
       the radio it arrived from: WL_MISMATCH means the enrolled station is not
       the one transmitting, so the override is withheld and the blocklist is
       allowed to do its work. Fail-open still applies when nothing matched at
       all (WL_NONE): an un-enrolled but allowlisted station is accepted, so
       adding the whitelist cannot make the satellite uncommandable.      */
    if (w == WL_MISMATCH)
      return m ? V_BLOCK : V_SPOOF_SUSPECT;
    return m ? V_ALLOW_OVERRIDE : V_ACCEPT;
  }
  return m ? V_BLOCK : V_ACCEPT;
}

/* Callsign-only form, kept for callers that have no whitelist loaded. */
static inline Verdict hny_verdict(const char *src, float freq_dev_khz,
                                  const BlockEntry **hit) {
  return hny_verdict_fp(src, freq_dev_khz, freq_dev_khz, nullptr, 0, hit, nullptr);
}

/* ══════════════════════ detection constants ══════════════════════════ */
static const uint8_t SEV_FREQ = 25, SEV_DOPP = 25, SEV_MOD = 15, SEV_CMD = 15,
                     SEV_MAL = 10, SEV_UNK = 5, SEV_PRB = 5;
static const float   FREQ_DEV_KHZ_TH = 20.0f, DOPP_RESID_HZ_TH = 700.0f,
                     PROBING_S_TH = 2.0f;
static const uint8_t FLAG_MIN = 50;
static const float   W_FREQ = 0.45f, W_DRIFT = 0.25f, W_MOD = 0.30f;
static const float   FUZZY_KNOWN_MIN = 0.85f, FUZZY_SUSP_MIN = 0.60f;
static const float   CONFIDENCE_CAP = 89.15f;
static const char   *SUSP_CMDS[] = {"REBOOT", "OVERRIDE", "0x7F_UNKNOWN_OPCODE",
                                    "ERASE_FLASH", "SET_MODE=DEBUG", "DISABLE_COMMS"};
static const size_t  N_SUS = sizeof(SUSP_CMDS) / sizeof(SUSP_CMDS[0]);
static const char   *BENIGN_CMDS[] = {"TLM_REQ", "HK_DUMP", "PING",
                                      "SET_MODE=NOMINAL", "TIME_SYNC",
                                      "PASS_SCHEDULE", "EPS_STATUS"};
static const size_t  N_BEN = sizeof(BENIGN_CMDS) / sizeof(BENIGN_CMDS[0]);

/* ══════════════════════ CTI record ════════════════════════════════════ */
struct Record {
  uint32_t t_ms;
  char     src[10];
  char     cmd[20];
  float    freq_dev_khz;
  float    dop_hz;
  float    rssi;
  uint8_t  crc_ok;
  float    gap_s;
  uint8_t  score;
  float    fuzzy;
  char     cls[12];
  uint8_t  flagged;
  float    conf;
  char     fp[21];          // 20 hex + NUL (filled by ESP32 sketch)
  char     sig[18];         // transmitter signature, e.g. "GS104@+0.0"
  uint8_t  wl;              // fingerprint whitelist: see WlState
};

static inline bool cmd_suspicious(const char *cmd) {
  for (size_t j = 0; j < N_SUS; j++) if (!strcmp(cmd, SUSP_CMDS[j])) return true;
  return false;
}

/* 7-indicator score + fuzzy match. Fills score/fuzzy/cls/flagged/conf.
   (Fingerprint is computed by the caller — SHA lives in the ESP32 sketch.)  */
static inline void hny_score(Record &r) {
  uint8_t s = 0;
  if (fabsf(r.freq_dev_khz) > FREQ_DEV_KHZ_TH) s += SEV_FREQ;
  if (fabsf(r.dop_hz)       > DOPP_RESID_HZ_TH) s += SEV_DOPP;
  if (cmd_suspicious(r.cmd))                    s += SEV_CMD;
  if (!r.crc_ok)                                s += SEV_MAL;
  if (strncmp(r.src, "GS", 2))                  s += SEV_UNK;
  if (r.gap_s < PROBING_S_TH)                   s += SEV_PRB;
  // modulation indicator: an SX127x packet receiver decodes only its own
  // modulation, so this indicator never fires on the bench

  float best = 0.0f, drift = 0.0f;      // drift not measurable on the bench
  for (size_t j = 0; j < N_GS; j++) {
    float sf = 1.0f - fabsf(r.freq_dev_khz - REGISTRY[j].bias_khz) / 25.0f;
    float sd = 1.0f - fabsf(drift - REGISTRY[j].drift_ppm) / 1.0f;
    if (sf < 0) sf = 0; if (sd < 0) sd = 0;
    float sc = W_FREQ * sf + W_DRIFT * sd + W_MOD * 1.0f;   // modulation matches
    if (sc > best) best = sc;
  }
  r.score   = s;
  r.fuzzy   = best;
  r.flagged = (s >= FLAG_MIN) ? 1 : 0;
  float c = 42.0f + 0.53f * (float)s;
  r.conf = (c > CONFIDENCE_CAP) ? CONFIDENCE_CAP : c;
  snprintf(r.cls, sizeof(r.cls), "%s",
           best >= FUZZY_KNOWN_MIN ? "known"
           : (best >= FUZZY_SUSP_MIN ? "suspicious" : "attacker"));
}

/* CSV form of a record, the line format the ground station prints and
   hny_server.py parses. The field order is fixed.                           */
static inline size_t record_to_csv(const Record &r, char *o, size_t cap) {
  return snprintf(o, cap,
                  "%lu,%s,%s,%.2f,%.0f,%.1f,%u,%.2f,%u,%.3f,%s,%u,%.2f,%s,%s,%u",
                  (unsigned long)r.t_ms, r.src, r.cmd, r.freq_dev_khz, r.dop_hz,
                  r.rssi, r.crc_ok, r.gap_s, r.score, r.fuzzy, r.cls,
                  r.flagged, r.conf, r.fp, r.sig, r.wl);
}

/* ═════════════ downlink wire record ══════════════════════════════════
   The SX1278's FSK FIFO is 64 bytes, and the driver reads it only once the
   packet is complete, so a frame longer than that is never delivered: the
   receiver reports a strong carrier and decodes nothing. A CTI record in CSV
   form is about 104 bytes, which is 122 on the air once AX.25 has added its
   18 — comfortably past the limit, and silently so.

   Records therefore downlink PACKED: 42 bytes, 60 on the air, and the ground
   station expands them back into exactly the CSV line the server already
   parses. Two consequences are deliberate and worth stating:

     - Fields the ground recomputes anyway are not sent. The class and the
       confidence follow from the fuzzy score and the anomaly score, and the
       transmitter signature follows from the callsign and the residual, so
       all three are derived at the ground station rather than carried.
     - The per-record SHA-256 is not sent either. It is a record identifier,
       not a transmitter identity, and spending 20 of 46 available
       payload bytes on an identifier the ground can assign itself is not a
       trade worth making on a 9.6 kb/s link.

   Quantisation: carrier offsets in 10 Hz units (±327 kHz range, 10 Hz step —
   an order finer than the 0.4 kHz the receiver itself resolves), gap in 0.1 s
   saturating at 25.5 s, fuzzy score in hundredths.                        */
struct __attribute__((packed)) RecordWire {
  uint32_t t_ms;
  char     src[7];        // callsigns are at most 6 characters
  char     cmd[20];       // longest bench command is 19 ("0x7F_UNKNOWN_OPCODE")
  int16_t  dev_dahz;      // measured carrier offset
  int16_t  res_dahz;      // offset after the common-mode Doppler is removed
  int16_t  dop_dahz;      // Doppler residual (the indicator's input)
  int8_t   rssi_dbm;
  uint8_t  gap_ds;
  uint8_t  fuzzy_x100;
  uint8_t  score;
  uint8_t  flags;         // b0 crc_ok, b1 flagged, b2-3 whitelist state
};

static inline int16_t _sat16(float v) {
  if (v > 32767.0f) return 32767;
  if (v < -32768.0f) return -32768;
  return (int16_t)(v < 0 ? v - 0.5f : v + 0.5f);
}

static inline void record_pack(const Record &r, float resid_khz, RecordWire &w) {
  memset(&w, 0, sizeof(w));
  w.t_ms = r.t_ms;
  strncpy(w.src, r.src, sizeof(w.src) - 1);
  strncpy(w.cmd, r.cmd, sizeof(w.cmd) - 1);
  w.dev_dahz = _sat16(r.freq_dev_khz * 100.0f);
  w.res_dahz = _sat16(resid_khz * 100.0f);
  w.dop_dahz = _sat16(r.dop_hz / 10.0f);
  w.rssi_dbm = (int8_t)(r.rssi < -128 ? -128 : (r.rssi > 127 ? 127 : r.rssi));
  float gds = r.gap_s * 10.0f;
  w.gap_ds = (uint8_t)(gds < 0 ? 0 : (gds > 255 ? 255 : gds));
  float fz = r.fuzzy * 100.0f;
  w.fuzzy_x100 = (uint8_t)(fz < 0 ? 0 : (fz > 255 ? 255 : fz));
  w.score = r.score;
  w.flags = (uint8_t)((r.crc_ok ? 1 : 0) | (r.flagged ? 2 : 0) | ((r.wl & 3) << 2));
}

/* Expand a wire record into the CSV line hny_server.py parses. Run on the CTI
   ground station, not on the honeypot: the satellite spends its airtime on
   measurements, and the ground spends its cycles on formatting.           */
static inline size_t wire_to_csv(const RecordWire &w, char *o, size_t cap) {
  char src[8] = {0}, cmd[21] = {0}, sig[18];
  memcpy(src, w.src, sizeof(w.src));
  memcpy(cmd, w.cmd, sizeof(w.cmd));
  float dev = w.dev_dahz / 100.0f, res = w.res_dahz / 100.0f;
  float fuzzy = w.fuzzy_x100 / 100.0f;
  hny_signature(src, res, sig, sizeof(sig));
  float conf = 42.0f + 0.53f * (float)w.score;
  if (conf > CONFIDENCE_CAP) conf = CONFIDENCE_CAP;
  const char *cls = fuzzy >= FUZZY_KNOWN_MIN ? "known"
                  : (fuzzy >= FUZZY_SUSP_MIN ? "suspicious" : "attacker");
  return snprintf(o, cap,
                  "%lu,%s,%s,%.2f,%.0f,%.1f,%u,%.2f,%u,%.3f,%s,%u,%.2f,,%s,%u",
                  (unsigned long)w.t_ms, src, cmd, dev,
                  (float)w.dop_dahz * 10.0f, (float)w.rssi_dbm,
                  (unsigned)(w.flags & 1), w.gap_ds / 10.0f, w.score, fuzzy,
                  cls, (unsigned)((w.flags >> 1) & 1), conf, sig,
                  (unsigned)((w.flags >> 2) & 3));
}
