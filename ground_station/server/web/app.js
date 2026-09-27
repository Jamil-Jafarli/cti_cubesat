"use strict";
/* CTI platform console.
 *
 * Six views over one capture: an overview, the alert queue the detection rules
 * fill, the raw telemetry, the attribution picture, the indicators this bench
 * is willing to share, and what the satellite itself is actually enforcing.
 *
 * Polls hny_server.py. Only the active tab's endpoint is fetched on each tick,
 * plus /api/state for the KPI row, so a long capture does not turn the browser
 * into the bottleneck.
 *
 * Charts are inline SVG built here: the server ships no libraries, and the
 * three forms needed (stacked bars over time, labelled severity bars, a dot
 * plot with ranges) are a few dozen lines each.
 */

const $ = (s) => document.querySelector(s);
const REFRESH_MS = 2500;

const S = {
  state: null, alerts: null, indicators: null, attribution: null,
  policy: null, timeseries: null, packets: [],
};
const F = {
  tab: "overview", query: "", alertStatus: "open", alertSev: "",
  src: "", cls: "", flaggedOnly: false, minConf: 50, indType: "",
  selAlert: null, selPacket: null, analysis: null,
};

const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString("en-GB");
const fmtDate = (ts) => new Date(ts * 1000).toLocaleString("en-GB");
const sign = (n, d = 1) => (n >= 0 ? "+" : "") + Number(n).toFixed(d);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

/* ── tooltip layer ────────────────────────────────────────────────────── */
let tipEl = null;
function showTip(ev, html) {
  if (!tipEl) {
    tipEl = document.createElement("div");
    tipEl.className = "tip";
    document.body.appendChild(tipEl);
  }
  tipEl.innerHTML = html;
  tipEl.style.display = "block";
  const pad = 14;
  const w = tipEl.offsetWidth, h = tipEl.offsetHeight;
  let x = ev.clientX + pad, y = ev.clientY + pad;
  if (x + w > window.innerWidth - 8) x = ev.clientX - w - pad;
  if (y + h > window.innerHeight - 8) y = ev.clientY - h - pad;
  tipEl.style.left = x + "px";
  tipEl.style.top = y + "px";
}
function hideTip() { if (tipEl) tipEl.style.display = "none"; }

/* ── charts ───────────────────────────────────────────────────────────── */

const SEV_COLOR = {
  critical: "var(--st-critical)", high: "var(--st-serious)",
  medium: "var(--st-warning)", low: "var(--ink-dim)",
};

function svgEl(w, h) {
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" role="img">`;
}

/* An SVG with a fixed height and a viewBox wider than its box gets letterboxed:
   the drawing is scaled to fit the height and centred, leaving dead margins.
   Measuring the host and drawing at that width keeps 1 user unit = 1 px, so
   text stays the size it was specified at whatever the window is doing. */
function hostWidth(host, fallback) {
  return Math.max(320, Math.floor(host.getBoundingClientRect().width) || fallback);
}

/* Stacked bars: captured frames per interval, flagged share stacked on top.
   Both series are counts of the same thing, so they share one axis; the 2px
   gap between the segments is the spacer the mark spec asks for. */
function chartTimeline(host, ts) {
  const b = ts.buckets || [];
  if (!b.length) { host.innerHTML = '<p class="empty">No traffic captured yet.</p>'; return; }
  const W = hostWidth(host, 640), H = 190, L = 34, R = 8, T = 10, B = 24;
  const max = Math.max(1, ...b.map((x) => x.frames));
  const iw = W - L - R, ih = H - T - B;
  const bw = Math.max(2, iw / b.length - 2);
  const y = (v) => T + ih - (v / max) * ih;
  let s = svgEl(W, H);
  // two gridlines is enough context for counts this small
  for (const gv of [max, max / 2]) {
    s += `<line class="grid-line" x1="${L}" x2="${W - R}" y1="${y(gv)}" y2="${y(gv)}"/>`
       + `<text x="4" y="${y(gv) + 4}">${Math.round(gv)}</text>`;
  }
  s += `<line class="grid-line" x1="${L}" x2="${W - R}" y1="${y(0)}" y2="${y(0)}"/>`;
  b.forEach((d, i) => {
    const x = L + i * (iw / b.length);
    const clean = d.frames - d.flagged;
    const hF = (d.flagged / max) * ih, hC = (clean / max) * ih;
    const topRound = d.flagged ? 4 : 4;
    if (clean > 0) {
      const yc = y(clean);
      s += `<rect x="${x}" y="${yc}" width="${bw}" height="${Math.max(1, hC)}"`
         + ` rx="${d.flagged ? 0 : topRound}" fill="var(--series-1)"/>`;
    }
    if (d.flagged > 0) {
      // 2px surface gap between the two fills, so the boundary reads as a
      // boundary and not as a third value
      const yf = y(d.frames) ;
      s += `<rect x="${x}" y="${yf}" width="${bw}" height="${Math.max(1, hF - 2)}"`
         + ` rx="4" fill="var(--st-critical)"/>`;
    }
    s += `<rect class="hit" x="${x - 1}" y="${T}" width="${bw + 2}" height="${ih}"`
       + ` data-i="${i}"/>`;
  });
  s += `<text x="${L}" y="${H - 6}">${fmtTime(b[0].t)}</text>`
     + `<text x="${W - R}" y="${H - 6}" text-anchor="end">${fmtTime(b[b.length - 1].t)}</text>`
     + `</svg>`;
  host.innerHTML = s;
  host.querySelectorAll(".hit").forEach((el) => {
    el.addEventListener("mousemove", (ev) => {
      const d = b[+el.dataset.i];
      showTip(ev, `<b>${fmtTime(d.t)}</b><br>`
        + `<span class="t-k">frames</span> ${d.frames}<br>`
        + `<span class="t-k">flagged</span> ${d.flagged}<br>`
        + `<span class="t-k">mean score</span> ${d.mean_score}`);
    });
    el.addEventListener("mouseleave", hideTip);
  });
  $("#legend-timeline").innerHTML =
    `<span class="k"><i style="background:var(--series-1)"></i>captured</span>`
    + `<span class="k"><i style="background:var(--st-critical)"></i>flagged (score ≥ 50)</span>`
    + `<span class="k">interval ${ts.bucket_s}s</span>`;
}

/* Severity: horizontal bars, every bar directly labelled. Warning and serious
   are too close in hue to carry meaning alone, so the label is the encoding
   and the colour only reinforces it. */
function chartSeverity(host, sum) {
  const rows = ["critical", "high", "medium", "low"].map((k) => ({ k, n: sum[k] || 0 }));
  const max = Math.max(1, ...rows.map((r) => r.n));
  const W = hostWidth(host, 320), rowH = 30, H = rows.length * rowH + 8,
        L = 74, R = 34;
  let s = svgEl(W, H);
  rows.forEach((r, i) => {
    const y = i * rowH + 8, w = (r.n / max) * (W - L - R);
    s += `<text x="${L - 8}" y="${y + 12}" text-anchor="end">${r.k}</text>`
       + `<rect x="${L}" y="${y + 2}" width="${Math.max(2, w)}" height="12" rx="4"`
       + ` fill="${SEV_COLOR[r.k]}"/>`
       + `<text class="val" x="${L + Math.max(2, w) + 6}" y="${y + 12}">${r.n}</text>`;
  });
  host.innerHTML = s + "</svg>";
}

/* Attribution: one row per source, the observed carrier-offset range as a
   whisker and the mean as the mark. Colour is a state (does this transmitter
   track the pass?), so it comes from the status palette and is repeated in the
   legend and in the table below. */
function chartAttribution(host, sources) {
  if (!sources.length) { host.innerHTML = '<p class="empty">No sources yet.</p>'; return; }
  const rows = sources.slice(0, 12);
  const lo = Math.min(...rows.map((r) => r.min_khz), -10);
  const hi = Math.max(...rows.map((r) => r.max_khz), 10);
  const pad = (hi - lo) * 0.08 || 1;
  const W = hostWidth(host, 720), rowH = 26, H = rows.length * rowH + 40,
        L = 76, R = 16, T = 14;
  const x = (v) => L + ((v - (lo - pad)) / ((hi + pad) - (lo - pad))) * (W - L - R);
  let s = svgEl(W, H);
  for (const gv of [lo, 0, hi]) {
    s += `<line class="grid-line" x1="${x(gv)}" x2="${x(gv)}" y1="${T}" y2="${T + rows.length * rowH}"`
       + (gv === 0 ? ' stroke-dasharray="3 3"' : "") + "/>"
       + `<text x="${x(gv)}" y="${H - 14}" text-anchor="middle">${sign(gv, 0)} kHz</text>`;
  }
  rows.forEach((r, i) => {
    const y = T + i * rowH + rowH / 2;
    const col = r.tracks_pass ? "var(--series-1)" : "var(--st-critical)";
    s += `<text x="${L - 10}" y="${y + 4}" text-anchor="end">${esc(r.src)}</text>`
       + `<line x1="${x(r.min_khz)}" x2="${x(r.max_khz)}" y1="${y}" y2="${y}"`
       + ` stroke="${col}" stroke-width="2" opacity=".55"/>`
       + `<circle cx="${x(r.mean_freq_dev_khz)}" cy="${y}" r="5" fill="${col}"`
       + ` stroke="var(--panel2)" stroke-width="2"/>`
       + `<rect class="hit" x="${L}" y="${y - rowH / 2}" width="${W - L - R}" height="${rowH}"`
       + ` data-i="${i}"/>`;
  });
  host.innerHTML = s + "</svg>";
  host.querySelectorAll(".hit").forEach((el) => {
    el.addEventListener("mousemove", (ev) => {
      const r = rows[+el.dataset.i];
      showTip(ev, `<b>${esc(r.src)}</b> · ${r.count} frames<br>`
        + `<span class="t-k">mean offset</span> ${sign(r.mean_freq_dev_khz, 2)} kHz<br>`
        + `<span class="t-k">range</span> ${sign(r.min_khz, 1)} … ${sign(r.max_khz, 1)} kHz<br>`
        + `<span class="t-k">mean |residual|</span> ${r.mean_abs_residual_hz} Hz<br>`
        + `<span class="t-k">registry</span> ${esc(r.registry_match)} (${r.registry_cls})`);
    });
    el.addEventListener("mouseleave", hideTip);
  });
  $("#legend-attribution").innerHTML =
    `<span class="k"><i style="background:var(--series-1)"></i>tracks the pass (Doppler pre-compensated)</span>`
    + `<span class="k"><i style="background:var(--st-critical)"></i>fixed carrier — not tracking</span>`;
}

/* ── KPI row ──────────────────────────────────────────────────────────── */
function renderKpis() {
  const k = (S.state && S.state.kpis) || {};
  const ind = S.indicators ? S.indicators.length : "–";
  const tiles = [
    { n: k.packets ?? "–", l: "Frames ingested",
      d: k.window_s ? `over ${Math.round(k.window_s)} s` : "" },
    { n: k.alerts_open ?? "–", l: "Open alerts",
      d: `${k.alerts_critical ?? 0} critical`, alarm: (k.alerts_critical ?? 0) > 0 },
    { n: k.flagged ?? "–", l: "Flagged frames",
      d: k.packets ? `${Math.round(100 * (k.flagged / k.packets))}% of capture` : "" },
    { n: k.sources ?? "–", l: "Sources seen", d: `${ind} indicators` },
    { n: k.candidates ?? "–", l: "Blocklist candidates", d: "confirmed & high risk" },
  ];
  $("#kpis").innerHTML = tiles.map((t) =>
    `<div class="kpi${t.alarm ? " alarm" : ""}"><div class="n">${t.n}</div>`
    + `<div class="l">${t.l}</div><div class="d">${t.d || ""}</div></div>`).join("");
}

/* ── overview ─────────────────────────────────────────────────────────── */
function renderOverview() {
  if (S.timeseries) chartTimeline($("#chart-timeline"), S.timeseries);
  if (S.state && S.state.alerts) chartSeverity($("#chart-severity"), S.state.alerts);

  const profs = (S.state && S.state.profiles) || [];
  $("#ov-sources").innerHTML = profs.length ? `<table class="fz-table">`
    + `<tr><th>Source</th><th>Risk</th><th>Frames</th><th>Flagged</th><th>Mean Δf</th></tr>`
    + profs.slice(0, 8).map((p) => `<tr><td class="mono">${esc(p.id)}</td>`
      + `<td><div class="riskcell"><div class="bar-track"><div class="bar-fill" style="width:${p.risk}%;`
      + `background:${p.risk >= 66 ? "var(--st-critical)" : p.risk >= 33 ? "var(--st-warning)" : "var(--series-1)"}"></div></div>`
      + `<span class="mono">${p.risk}</span></div></td>`
      + `<td>${p.count}</td><td>${p.flagged}</td>`
      + `<td class="mono">${sign(p.mean_freq_dev_khz, 2)} kHz</td></tr>`).join("")
    + `</table>` : '<p class="empty">Nothing captured yet.</p>';

  const al = (S.alerts && S.alerts.alerts) || [];
  $("#ov-alerts").innerHTML = al.length ? al.slice(0, 6).map((a) =>
    `<div class="alert-card" data-id="${a.id}"><div class="top">`
    + `<span class="sev ${a.severity}">${a.severity}</span>`
    + `<span class="note">${fmtTime(a.ts)}</span></div>`
    + `<div class="ttl">${esc(a.title)}</div>`
    + `<div class="meta">${esc(a.rule)} · ${esc(a.rule_name)} · ${esc(a.tactic || "")}</div></div>`
  ).join("") : '<p class="empty">No detections.</p>';
  $("#ov-alerts").querySelectorAll(".alert-card").forEach((el) =>
    el.addEventListener("click", () => {
      F.selAlert = +el.dataset.id; switchTab("alerts");
    }));
}

/* ── alerts ───────────────────────────────────────────────────────────── */
function alertMatches(a) {
  if (F.alertSev && a.severity !== F.alertSev) return false;
  if (!F.query) return true;
  const q = F.query.toLowerCase();
  return [a.title, a.entity, a.rule, a.rule_name, a.tactic]
    .some((v) => (v || "").toLowerCase().includes(q));
}

function renderAlerts() {
  const all = (S.alerts && S.alerts.alerts) || [];
  // land on something: an empty detail pane next to a full queue is a dead end
  if (F.selAlert === null && all.length) selectAlert(all[0].id);
  const shown = all.filter(alertMatches);
  $("#alert-count").textContent =
    `${shown.length} of ${all.length} shown · ${(S.alerts && S.alerts.summary.open) || 0} open in total`;
  $("#alert-list").innerHTML = shown.length ? shown.map((a) =>
    `<div class="alert-card${F.selAlert === a.id ? " sel" : ""}" data-id="${a.id}">`
    + `<div class="top"><span class="sev ${a.severity}">${a.severity}</span>`
    + `<span class="note">${fmtTime(a.ts)}</span></div>`
    + `<div class="ttl">${esc(a.title)}</div>`
    + `<div class="meta">${esc(a.rule)} ${esc(a.rule_name)} · ${esc(a.entity || "—")}`
    + ` · ${esc(a.status)}</div></div>`).join("")
    : '<p class="empty">Nothing matches.</p>';
  $("#alert-list").querySelectorAll(".alert-card").forEach((el) =>
    el.addEventListener("click", () => selectAlert(+el.dataset.id)));

  const a = all.find((x) => x.id === F.selAlert);
  if (!a) { $("#alert-detail").innerHTML = '<p class="empty">Select an alert.</p>'; return; }
  const rule = ((S.alerts && S.alerts.rules) || []).find((r) => r.id === a.rule) || {};
  $("#alert-detail").innerHTML =
    `<h2>${esc(a.title)}</h2>`
    + `<p class="note">${esc(a.rule)} · ${esc(rule.name || a.rule_name)} · tactic: `
    + `${esc(a.tactic || "—")} · first seen ${fmtDate(a.ts)}</p>`
    + `<div class="kv">`
    + box("Severity", `<span class="sev ${a.severity}">${a.severity}</span>`)
    + box("Entity", esc(a.entity || "—"))
    + box("Status", esc(a.status))
    + box("Frame", a.packet_id ? `#${a.packet_id}` : "—")
    + `</div>`
    + `<h3>Evidence</h3><table class="fz-table">`
    + Object.entries(a.detail || {}).map(([k, v]) =>
        `<tr><td class="mono">${esc(k)}</td><td class="mono">${esc(
          Array.isArray(v) ? v.join(", ") : v)}</td></tr>`).join("")
    + `</table>`
    + (F.analysis ? analysisHtml(F.analysis) : "")
    + `<div style="margin-top:12px">`
    + `<button class="btn ok" data-act="ack">Acknowledge</button> `
    + `<button class="btn" data-act="closed">Close</button> `
    + `<button class="btn" data-act="open">Reopen</button></div>`;
  $("#alert-detail").querySelectorAll("[data-act]").forEach((b) =>
    b.addEventListener("click", async () => {
      await fetch(`/api/alert/${a.id}`, {
        method: "POST", body: JSON.stringify({ status: b.dataset.act }),
      });
      await refresh(true);
    }));
}

async function selectAlert(id) {
  F.selAlert = id;
  const all = (S.alerts && S.alerts.alerts) || [];
  const a = all.find((x) => x.id === id);
  F.analysis = a && a.packet_id
    ? await getJSON(`/api/analysis/${a.packet_id}`).catch(() => null) : null;
  renderAlerts();
}

const box = (l, v) => `<div class="box"><div class="bl">${l}</div><div class="bv">${v}</div></div>`;

/* How a number became a verdict: the onboard fuzzy match, term by term. */
function analysisHtml(an) {
  const f = an.fuzzy, p = an.packet;
  const rows = f.ranked.map((c) =>
    `<tr class="${c.id === f.best.id ? "best" : ""}"><td class="mono">${esc(c.id)}</td>`
    + `<td class="mono">${sign(c.bias_khz, 2)}</td><td class="mono">${sign(c.delta_khz, 2)}</td>`
    + `<td class="mono">${c.freq_term.toFixed(3)}</td><td class="mono">${c.drift_term.toFixed(3)}</td>`
    + `<td class="mono">${c.mod_term.toFixed(2)}</td><td class="mono">${c.score.toFixed(3)}</td></tr>`).join("");
  return `<h3>Onboard fuzzy match</h3>`
    + `<p class="note">score = ${f.weights.freq} × frequency + ${f.weights.drift} × drift`
    + ` + ${f.weights.modulation} × modulation. Classified <b>${esc(f.cls)}</b> at`
    + ` ${f.best.score.toFixed(3)} (known ≥ ${f.thresholds.known}, suspicious ≥ ${f.thresholds.suspicious}),`
    + ` margin over the runner-up ${f.margin.toFixed(3)}.`
    + ` Drift is <b>not measured</b> on this hardware, so that quarter of the score is a`
    + ` constant per registry entry and the ranking rests on the carrier offset alone.</p>`
    + `<table class="fz-table"><tr><th>Registry</th><th>bias</th><th>Δ</th>`
    + `<th>freq term</th><th>drift term</th><th>mod</th><th>score</th></tr>${rows}</table>`
    + `<h3>Onboard verdict</h3><div class="kv">`
    + box("Signature", `<span class="mono">${esc(an.signature)}</span>`)
    + box("Whitelist", `<span class="wl-${p.wl ?? 0}">${esc(an.onboard.whitelist)}</span>`)
    + box("Onboard score", esc(an.onboard.score ?? "—"))
    + box("Onboard class", esc(an.onboard.cls ?? "—"))
    + `</div>`
    + (an.rules_fired.length
      ? `<h3>Rules this frame fires</h3>` + an.rules_fired.map((r) =>
          `<div class="meta"><span class="sev ${r.severity}">${r.severity}</span> `
          + `<span class="mono">${esc(r.rule)}</span> ${esc(r.title)}</div>`).join("")
      : "");
}

/* ── telemetry ────────────────────────────────────────────────────────── */
function telMatches(r) {
  if (F.src && r.src !== F.src) return false;
  if (F.cls && r.cls !== F.cls) return false;
  if (F.flaggedOnly && !r.flagged) return false;
  if (!F.query) return true;
  const q = F.query.toLowerCase();
  return [r.src, r.cmd, r.sig, r.fp].some((v) => (v || "").toLowerCase().includes(q));
}

function renderTelemetry() {
  const rows = S.packets.filter(telMatches);
  const srcs = [...new Set(S.packets.map((r) => r.src).filter(Boolean))].sort();
  const sel = $("#f-src");
  if (sel.options.length !== srcs.length + 1) {
    sel.innerHTML = `<option value="">any</option>`
      + srcs.map((s) => `<option${s === F.src ? " selected" : ""}>${esc(s)}</option>`).join("");
  }
  $("#tel-count").textContent = `${rows.length} of ${S.packets.length} frames`;
  $("#tel-body").innerHTML = rows.slice(0, 300).map((r) =>
    `<tr class="pick${r.flagged ? " flag" : ""}${F.selPacket === r.id ? " sel" : ""}" data-id="${r.id}">`
    + `<td>${fmtTime(r.ts)}</td><td class="mono">${esc(r.src)}</td>`
    + `<td class="mono">${esc(r.cmd)}</td>`
    + `<td class="mono">${sign(r.freq_dev_khz, 2)}</td>`
    + `<td class="mono">${r.dop_hz === null ? "–" : sign(r.dop_hz, 0)}</td>`
    + `<td class="mono">${r.rssi}</td>`
    + `<td>${r.crc_ok ? "ok" : '<span class="wl-2">bad</span>'}</td>`
    + `<td class="mono">${esc(r.sig || "–")}</td>`
    + `<td class="wl-${r.wl ?? 0}">${{ 0: "none", 1: "match", 2: "MISMATCH" }[r.wl] ?? "–"}</td>`
    + `<td>${r.score}</td><td><span class="tag ${esc(r.cls)}">${esc(r.cls)}</span></td></tr>`).join("");
  $("#tel-body").querySelectorAll("tr").forEach((el) =>
    el.addEventListener("click", async () => {
      F.selPacket = +el.dataset.id;
      F.analysis = await getJSON(`/api/analysis/${F.selPacket}`).catch(() => null);
      renderTelemetry();
    }));
  $("#tel-detail").innerHTML = F.analysis && F.selPacket
    ? `<h2>Frame #${F.selPacket} — ${esc(F.analysis.packet.src)} `
      + `${esc(F.analysis.packet.cmd)}</h2>` + analysisHtml(F.analysis)
    : '<p class="empty">Select a frame to see how it was scored.</p>';
}

/* ── attribution ──────────────────────────────────────────────────────── */
function renderAttribution() {
  if (!S.attribution) return;
  chartAttribution($("#chart-attribution"), S.attribution.sources);
  $("#attr-table").innerHTML = `<table class="fz-table">`
    + `<tr><th>Source</th><th>Frames</th><th>Mean Δf</th><th>Spread</th>`
    + `<th>Mean |residual|</th><th>Tracks pass</th><th>Registry match</th>`
    + `<th>Class</th><th>Signatures</th></tr>`
    + S.attribution.sources.map((s) => `<tr>`
      + `<td class="mono">${esc(s.src)}</td><td>${s.count}</td>`
      + `<td class="mono">${sign(s.mean_freq_dev_khz, 2)} kHz</td>`
      + `<td class="mono">±${s.spread_khz} kHz</td>`
      + `<td class="mono">${s.mean_abs_residual_hz} Hz</td>`
      + `<td>${s.tracks_pass ? "yes" : '<span class="wl-2">no</span>'}</td>`
      + `<td class="mono">${esc(s.registry_match)} (${s.registry_score.toFixed(3)})</td>`
      + `<td><span class="tag ${esc(s.registry_cls)}">${esc(s.registry_cls)}</span></td>`
      + `<td class="mono">${esc((s.signatures || []).join(" "))}</td></tr>`).join("")
    + `</table>`;
  $("#fuzzy-explainer").innerHTML =
    `<h3>How attribution is decided</h3>`
    + `<p class="note">Two independent questions. <b>Who does this look like?</b> is the`
    + ` onboard fuzzy match against the 16-entry registry — carrier offset (weight 0.45),`
    + ` oscillator drift (0.25, not measurable on this bench) and modulation (0.30).`
    + ` <b>Is it really them?</b> is the Doppler residual: a station that tracks the`
    + ` satellite pre-compensates its carrier, so its residual stays near zero, while a`
    + ` transmitter parked on a fixed frequency carries the whole pass profile. A frame`
    + ` can score as <i>known</i> on the first question and still fail the second —`
    + ` that combination is exactly what callsign impersonation looks like.</p>`
    + `<p class="note">Registry (bias kHz / drift ppm): `
    + S.attribution.registry.map((r) =>
        `<span class="chip">${esc(r.id)} ${sign(r.bias_khz, 2)} / ${r.drift_ppm}</span>`).join(" ")
    + `</p>`;
}

/* ── indicators ───────────────────────────────────────────────────────── */
function renderIndicators() {
  const all = S.indicators || [];
  const shown = all.filter((i) =>
    i.confidence >= F.minConf
    && (!F.indType || i.type === F.indType)
    && (!F.query || i.value.toLowerCase().includes(F.query.toLowerCase())));
  $("#ind-table").innerHTML = `<table class="fz-table">`
    + `<tr><th>Type</th><th>Indicator</th><th>Confidence</th><th>Frames</th>`
    + `<th>Flagged</th><th>Mean Δf</th><th>TLP</th><th>Tactics</th>`
    + `<th>Disposition</th></tr>`
    + shown.map((i) => `<tr>`
      + `<td>${esc(i.type)}</td><td class="mono">${esc(i.value)}</td>`
      + `<td><div class="riskcell"><div class="bar-track"><div class="bar-fill" style="width:${i.confidence}%"></div></div>`
      + `<span class="mono">${i.confidence}</span></div></td>`
      + `<td>${i.count}</td><td>${i.flagged}</td>`
      + `<td class="mono">${sign(i.mean_freq_dev_khz, 2)} ±${i.spread_khz}</td>`
      + `<td><span class="tag ${i.tlp === "TLP:AMBER" ? "suspicious" : "known"}">${esc(i.tlp)}</span></td>`
      + `<td class="note">${esc((i.tactics || []).join(", ") || "—")}</td>`
      + `<td><select class="ind-st" data-v="${esc(i.value)}">`
      + ["watch", "blocklist", "allowlist", "dismissed"].map((s) =>
          `<option${s === i.status ? " selected" : ""}>${s}</option>`).join("")
      + `</select></td></tr>`).join("")
    + `</table>`;
  $("#ind-table").querySelectorAll(".ind-st").forEach((sel) =>
    sel.addEventListener("change", async () => {
      await fetch("/api/indicator", {
        method: "POST",
        body: JSON.stringify({ value: sel.dataset.v, status: sel.value }),
      });
      await refresh(true);
    }));
  const q = `?min_confidence=${F.minConf}`;
  $("#dl-stix").href = "/api/export/stix" + q;
  $("#dl-misp").href = "/api/export/misp" + q;
  $("#dl-csv").href = "/api/export/csv" + q;
}

/* ── onboard policy ───────────────────────────────────────────────────── */
function renderPolicy() {
  const p = S.policy;
  if (!p) return;
  $("#policy-body").innerHTML =
    `<h3>What the satellite enforces right now</h3>`
    + `<div class="kv">`
    + box("Allowlist (callsign + enrolled RF signature)",
         p.onboard_allowlist.map((c) => `<span class="chip">${esc(c)}</span>`).join(" "))
    + box("Blocklist entries", String(p.onboard_blocklist.length))
    + box("Minimum confidence to block", String(p.block_conf_min))
    + `</div>`
    + `<table class="fz-table"><tr><th>Callsign</th><th>Carrier</th><th>Tolerance</th>`
    + `<th>Confidence</th><th>Acted on</th></tr>`
    + p.onboard_blocklist.map((b) => `<tr><td class="mono">${esc(b.call)}</td>`
      + `<td class="mono">${sign(b.bias_khz, 1)} kHz</td>`
      + `<td class="mono">±${b.tol_khz} kHz</td><td>${b.conf}</td>`
      + `<td>${b.conf >= p.block_conf_min ? "yes" : "below threshold"}</td></tr>`).join("")
    + `</table>`
    + `<h3 style="margin-top:16px">Ground picture vs. the satellite</h3>`
    + `<div class="kv">`
    + box("Proposed for blocking",
         p.proposed_blocklist.map((c) => `<span class="chip bad">${esc(c)}</span>`).join(" ") || "—")
    + box("Not yet uplinked",
         p.not_yet_uplinked.map((c) => `<span class="chip bad">${esc(c)}</span>`).join(" ") || "—")
    + box("On board but no longer proposed",
         p.stale_onboard.map((c) => `<span class="chip">${esc(c)}</span>`).join(" ") || "—")
    + `</div>`
    + `<p class="note">The allowlist always wins over the blocklist, so an attacker`
    + ` cannot get a legitimate station locked out by imitating it. The`
    + ` override is granted only when the <b>RF signature</b> matches the enrolled`
    + ` one as well as the callsign: a spoofer that transmits a whitelisted callsign`
    + ` from its own radio is reported as a mismatch instead, which is what the`
    + ` <span class="mono">WL</span> column in Telemetry shows. Enrolment happens on`
    + ` the board itself (<span class="mono">A</span> on the serial console);`
    + ` <span class="mono">F</span> lists the table.</p>`;
}

/* ── tabs, filters, polling ───────────────────────────────────────────── */
const TABS = ["overview", "alerts", "telemetry", "attribution", "indicators", "policy"];

function switchTab(name) {
  F.tab = TABS.includes(name) ? name : "overview";
  if (location.hash.slice(1) !== F.tab) location.hash = F.tab;
  document.querySelectorAll("#tabs button").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll("main .tab").forEach((d) =>
    d.hidden = d.id !== "tab-" + name);
  refresh(true);
}

async function refresh(force) {
  try {
    S.state = await getJSON("/api/state");
    $("#ingest").textContent = `${S.state.kpis.packets} frames`;
    $("#ingest").className = "pill-live " + (S.state.kpis.packets ? "live" : "idle");
    if (F.tab === "overview" || force) {
      S.timeseries = await getJSON("/api/timeseries");
      S.alerts = await getJSON(`/api/alerts?status=${F.alertStatus}`);
    }
    if (F.tab === "alerts") S.alerts = await getJSON(`/api/alerts?status=${F.alertStatus}`);
    if (F.tab === "telemetry") S.packets = await getJSON("/api/packets");
    if (F.tab === "attribution") S.attribution = await getJSON("/api/attribution");
    if (F.tab === "indicators" || force) S.indicators = await getJSON("/api/indicators")
      .then((d) => d.indicators);
    if (F.tab === "policy") S.policy = await getJSON("/api/policy");
  } catch (e) {
    $("#ingest").textContent = "server unreachable";
    $("#ingest").className = "pill-live idle";
    return;
  }
  renderKpis();
  ({ overview: renderOverview, alerts: renderAlerts, telemetry: renderTelemetry,
     attribution: renderAttribution, indicators: renderIndicators,
     policy: renderPolicy }[F.tab] || (() => {}))();
  $("#updated").textContent = new Date().toLocaleTimeString("en-GB");
}

document.querySelectorAll("#tabs button").forEach((b) =>
  b.addEventListener("click", () => switchTab(b.dataset.tab)));
$("#search").addEventListener("input", (e) => { F.query = e.target.value; refresh(); });
$("#f-alert-status").addEventListener("change", (e) => { F.alertStatus = e.target.value; refresh(true); });
$("#f-alert-sev").addEventListener("change", (e) => { F.alertSev = e.target.value; renderAlerts(); });
$("#f-src").addEventListener("change", (e) => { F.src = e.target.value; renderTelemetry(); });
$("#f-cls").addEventListener("change", (e) => { F.cls = e.target.value; renderTelemetry(); });
$("#f-flagged").addEventListener("change", (e) => { F.flaggedOnly = e.target.checked; renderTelemetry(); });
$("#f-ind-type").addEventListener("change", (e) => { F.indType = e.target.value; renderIndicators(); });
$("#f-conf").addEventListener("input", (e) => {
  F.minConf = +e.target.value; $("#f-conf-v").textContent = e.target.value;
  renderIndicators();
});

let resizeT = null;
window.addEventListener("resize", () => {
  clearTimeout(resizeT);
  resizeT = setTimeout(() => {
    if (F.tab === "overview" || F.tab === "attribution") refresh();
  }, 150);
});

window.addEventListener("hashchange", () => {
  const h = location.hash.slice(1);
  if (TABS.includes(h) && h !== F.tab) switchTab(h);
});

switchTab(location.hash.slice(1) || "overview");
setInterval(refresh, REFRESH_MS);
