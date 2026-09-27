"""Shared static profiles: known ground-station registry and honeypot node parameters.

Each known ground station has a stable transmitter signature (residual carrier
offset relative to the node center after Doppler pre-compensation, and
short-term oscillator drift). These
two parameters, together with the modem profile, form the fuzzy-match feature
space used for transmitter identification.
"""

# Honeypot node downlink/uplink center frequencies (MHz) and modem profile.
# All inside the 435-438 MHz amateur-satellite sub-band (IARU Region 1).
NODE_CENTERS_MHZ = {
    "HNY-1": 437.1000,
    "HNY-2": 437.3250,
    "HNY-3": 437.8500,
}
EXPECTED_MODULATION = "GFSK"

# Known cooperative ground stations: transmitter signature registry
# bias_khz  : residual carrier offset from the channel center after Doppler
#             pre-compensation; TCXO-class references keep this within
#             +-1 kHz (~ +-2.3 ppm at 437 MHz)
# drift_ppm : short-term oscillator stability (calibrated equipment < 0.15 ppm)
KNOWN_SOURCES = {
    "GS-100": {"bias_khz": 0.64,  "drift_ppm": 0.04},
    "GS-101": {"bias_khz": -0.82, "drift_ppm": 0.11},
    "GS-102": {"bias_khz": 0.41,  "drift_ppm": 0.06},
    "GS-103": {"bias_khz": -0.52, "drift_ppm": 0.09},
    "GS-104": {"bias_khz": 0.88,  "drift_ppm": 0.03},
    "GS-105": {"bias_khz": -0.23, "drift_ppm": 0.07},
    "GS-106": {"bias_khz": 0.19,  "drift_ppm": 0.12},
    "GS-107": {"bias_khz": -0.71, "drift_ppm": 0.05},
    "GS-108": {"bias_khz": 0.29,  "drift_ppm": 0.08},
    "GS-109": {"bias_khz": 0.81,  "drift_ppm": 0.02},
    "GS-110": {"bias_khz": -0.35, "drift_ppm": 0.10},
    "GS-111": {"bias_khz": 0.51,  "drift_ppm": 0.06},
    "GS-112": {"bias_khz": -0.93, "drift_ppm": 0.04},
    "GS-113": {"bias_khz": 0.12,  "drift_ppm": 0.09},
    "GS-114": {"bias_khz": -0.59, "drift_ppm": 0.11},
    "GS-115": {"bias_khz": 0.76,  "drift_ppm": 0.05},
}

BENIGN_COMMANDS = [
    "TLM_REQ", "HK_DUMP", "PING", "SET_MODE=NOMINAL",
    "TIME_SYNC", "PASS_SCHEDULE", "EPS_STATUS",
]
SUSPICIOUS_COMMANDS = [
    "REBOOT", "OVERRIDE", "0x7F_UNKNOWN_OPCODE",
    "ERASE_FLASH", "SET_MODE=DEBUG", "DISABLE_COMMS",
]
MALICIOUS_MODULATIONS = ["OFDM", "QPSK", "BPSK", "FSK"]

# Detection indicator severities (sum = 100). Mirrors the dashboard "Detection Logic".
INDICATOR_SEVERITY = {
    "frequency_deviation": 25,
    "doppler_mismatch": 25,
    "unexpected_modulation": 15,
    "suspicious_command": 15,
    "malformed_packet": 10,
    "unknown_source": 5,
    "aggressive_probing": 5,
}

INDICATOR_REASONS = {
    "frequency_deviation": "frequency deviation",
    "doppler_mismatch": "doppler mismatch",
    "unexpected_modulation": "unexpected modulation",
    "suspicious_command": "suspicious command",
    "malformed_packet": "malformed packet",
    "unknown_source": "unknown source id",
    "aggressive_probing": "aggressive probing rate",
}

# Indicator trigger thresholds
FREQ_DEV_THRESHOLD_KHZ = 20.0
DOPPLER_RESID_THRESHOLD_HZ = 700.0
PROBING_THRESHOLD_S = 2.0

# Fuzzy-match weights and classification bounds (see docs/detection.md)
FUZZY_W_FREQ, FUZZY_W_DRIFT, FUZZY_W_MOD = 0.45, 0.25, 0.30
FUZZY_KNOWN_MIN = 0.85
FUZZY_SUSPICIOUS_MIN = 0.60

# A packet at or above this anomaly score generates a CTI fingerprint record
FLAG_THRESHOLD = 50
