# Detection

Detection runs in two tiers. The honeypot node scores every frame as it
arrives, fingerprints the transmitter and stores a record. The ground station
receives the stored records, analyses the whole pass again with information
the satellite does not have, raises alerts and builds the threat-intelligence
picture. The ground figures are the authoritative ones; the onboard score is
kept alongside for comparison.

The same constants are defined in `libraries/HnyProto/HnyProto.h` (firmware),
`simulation/profiles.py` (synthetic pipeline) and
`ground_station/server/cti_engine.py` (ground analysis).

## Anomaly score

Every frame gets a score of 0–100, the sum of seven weighted binary
indicators:

| Indicator | Fires when | Weight |
|---|---|---:|
| Frequency deviation | carrier more than 20 kHz from the node's centre frequency | 25 |
| Doppler mismatch | Doppler residual larger than 700 Hz | 25 |
| Unexpected modulation | modulation differs from the expected profile (GFSK in the model) | 15 |
| Suspicious command | `REBOOT`, `OVERRIDE`, `ERASE_FLASH`, `SET_MODE=DEBUG`, `DISABLE_COMMS` or an unknown opcode | 15 |
| Malformed packet | AX.25 FCS does not verify | 10 |
| Unknown source | callsign not in the ground-station registry | 5 |
| Probing | less than 2 s since the previous frame | 5 |

A frame with a score of 50 or more is **flagged**, and a CTI record is
created for it. Its confidence is `min(89.15, 42 + 0.53 × score)`; the cap is
a calibration constant, not a measured value.

On the bench the modulation indicator never fires: an SX127x packet receiver
decodes only its own modulation and sees any other one as signal strength
alone. Recognising foreign modulations needs a receiver with IQ output or an
SDR at the ground station.

The Doppler residual is the carrier offset left after the pass Doppler and
the transmitter's known offset are removed. A cooperating ground station
pre-compensates the pass Doppler, so its residual is near zero; a transmitter
without an orbit model (a typical ground attacker) stays on a fixed frequency,
and its residual follows the whole pass profile.

## Fuzzy transmitter match

Independently of the score, every frame is compared with each of the 16
ground stations in the registry. A station's signature is the residual
carrier offset of its transmitter (sub-kHz for TCXO-class references) and its
short-term oscillator drift (ppm). The similarity with one entry is

```
S = 0.45 · (1 − |Δfreq| / 25 kHz)
  + 0.25 · (1 − |Δdrift| / 1 ppm)
  + 0.30 · [modulation matches]
```

with each term clipped at zero. The best match over the registry classifies
the transmitter as **known** (S ≥ 0.85), **suspicious** (0.60 ≤ S < 0.85) or
**attacker** (S < 0.60).

The bench measures the carrier offset to about 0.4 kHz and cannot measure
oscillator drift at all (the firmware passes zero), so on the bench the
ranking rests on the frequency term. The portal shows the three weighted
terms, the runner-up and the margin for every frame, so a classification that
rests on an unmeasured term is visible as such.

The fuzzy match is a 1:N identification and only works on a small,
mission-specific registry. With thousands of stations in one database almost
any ordinary transmitter would sit within 1 kHz of some entry and be
classified as `known` under another station's name. Decisions about a claimed
identity should therefore rest on a 1:1 check of the claimed callsign's own
signature, which is what the whitelist below does.

## Transmitter signature and fingerprint whitelist

The per-record SHA-256 identifier changes with every frame, so nothing can be
whitelisted on it. What does persist from frame to frame is the physical
layer the transmitter cannot easily change: the carrier offset its oscillator
lands on. Quantised to 0.5 kHz and paired with the claimed callsign, it forms
the **transmitter signature**:

```
GS104@+0.0     the operator's own station, as enrolled
GS104@+24.5    somebody else transmitting GS104's callsign
```

The honeypot keeps a small whitelist of signatures (up to 8 entries, stored
in flash). Each entry holds a callsign, an enrolled offset and a tolerance
(1.5 kHz). A frame is checked against it on its Doppler-free residual and
gets one of three states:

| State | Meaning |
|---|---|
| none | no entry for this callsign: the whitelist has no opinion |
| match | the callsign is enrolled and the offset is within tolerance |
| mismatch | the callsign is enrolled, but the frame came from a different transmitter |

Entries are enrolled deliberately: send `A` to the honeypot right after a
known-good frame. A flight build would fill the table before launch and
update it only through an authenticated uplink. Enrolment is trust on first
use: an impersonator transmitting during enrolment would be enrolled.

### Onboard Doppler estimate

The whitelist must be checked on the residual, and the bench board has no
orbit model. Every cooperating station pre-compensates the same pass profile,
so subtracting each station's known offset from its measured offset leaves
the common Doppler motion. The median of the last eight such samples
estimates it; a fixed-frequency attacker is an outlier the median ignores.
The estimate needs three samples from known callsigns before it is used
(about 20 s on the bench scenario); until then the residual is the raw offset.

Limits of this estimate: the median lags the fastest part of the pass, so a
legitimate frame can briefly exceed the 700 Hz threshold; and it assumes the
cooperating stations are the majority of the traffic. A flight board would
take the Doppler from its orbit propagator instead.

## Member mode

On a member satellite the board is a gate, not a sensor. For every uplink
frame it gives the on-board computer a verdict and stores nothing. Two lists
decide:

- the **allowlist**: the satellite's own ground stations; it always wins, so
  an attacker cannot get a legitimate station blocked by imitating it;
- the **blocklist**: transmitter signatures from the ground platform
  (callsign plus carrier offset within a tolerance). Only entries with a
  confidence of 80 or more are acted on.

| Situation | Verdict |
|---|---|
| blocklist match, callsign not allowlisted | BLOCK |
| allowlisted callsign, whitelist match or no entry, blocklist match | ACCEPT (allowlist override) |
| allowlisted callsign, whitelist mismatch, blocklist match | BLOCK |
| allowlisted callsign, whitelist mismatch, no blocklist match | ACCEPT, marked as spoof suspect |
| no match, or an undecodable frame | ACCEPT |

The board fails open: anything it cannot positively match is accepted, so a
false positive can never make the satellite uncommandable. The bench lists
are compiled into `HnyProto.h` (`ALLOWLIST`, `BLOCKLIST`); distributing the
ground-built blocklist to member satellites over RF is not implemented.

## Ground analysis

When the downlink goes quiet the server analyses the received records:

1. **Pass fit.** The honeypot and the transmitter boot independently, so
   their clocks differ by an unknown constant. The server scans the pass
   phase in one-second steps and takes the one that minimises the median
   Doppler residual of the known stations.
2. **Rescoring.** With the fitted pass, the Doppler residual and the score of
   every record are recomputed with the weights above. These are the
   authoritative figures; the honeypot's own score is kept as
   `onboard_score`.
3. **Detection rules.** Nine rules raise alerts:

| Rule | Name | Fires when | Severity | Tactic |
|---|---|---|---|---|
| RF-01 | Off-frequency carrier | carrier more than 20 kHz off centre | high | Initial Access |
| RF-02 | Doppler residual anomaly | Doppler residual larger than 700 Hz | high | Initial Access |
| ID-01 | Callsign impersonation | a registered callsign with such a residual | critical | Defense Evasion |
| ID-02 | Onboard whitelist mismatch | the honeypot reported a whitelist mismatch | critical | Defense Evasion |
| CMD-01 | Suspicious command | suspicious command; critical if destructive (`ERASE_FLASH`, `DISABLE_COMMS`, `OVERRIDE`) | medium / critical | Execution |
| REC-01 | Unregistered source | callsign outside the registry | medium | Reconnaissance |
| REC-02 | Probing burst | less than 2 s since the previous frame | medium | Reconnaissance |
| INT-01 | Malformed frame | AX.25 FCS does not verify | low | Defense Evasion |
| AGG-01 | Sustained campaign | five or more flagged frames from one source within ten minutes | critical | Impact |

The tactic labels follow the style of ATT&CK and are used for grouping only.
Alerts are keyed by rule and frame, so re-running the analysis over the same
capture does not duplicate them. In the portal they move from open to
acknowledged to closed.

REC-02 works on the gap the receiver sees, not per source, so a burst is also
attributed to the frame that follows it.

## Profiles, indicators and sharing

Records are grouped into **source profiles** by claimed callsign. The record
identifier cannot group traffic, and true transmitter grouping would need the
drift measurement the bench lacks. Each profile has a risk score:

```
severity = 30 · flagged share
         + 25 · share of suspicious commands
         + 20 · [callsign not registered]
         + 15 · min(1, count / 20)                persistence
         + 10 · min(1, mean |carrier offset| / 20 kHz)
risk     = min(100, severity · min(1, count / 3))
```

A profile needs at least three observations to count as confirmed, and a
confirmed profile with a risk of 60 or more becomes a blocklist candidate.
One frame, however suspicious, cannot produce a high-risk profile.

Callsigns, transmitter signatures and commands are offered as **indicators**,
each with its evidence count, a TLP marking (AMBER when flagged traffic is
involved, GREEN otherwise) and a confidence:

```
confidence = min(95, 40 · min(1, count / 10) + 35 · flagged share + 25 · offset consistency)
```

The confidence is capped below 100 on purpose: a bench of two radios cannot
earn certainty. The analyst sets each indicator's disposition (watch,
blocklist, allowlist, dismissed), and the indicator set exports as a STIX 2.1
bundle, a MISP event or CSV. RF properties have no standard STIX object type,
so they are exported as custom properties rather than forced into a network
indicator. A TAXII server is not implemented.
