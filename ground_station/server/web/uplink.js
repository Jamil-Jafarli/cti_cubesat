"use strict";
// Uplink monitor: live list of the frames gs_uplink_pico transmits.
// Polls uplink_ui.py: GET /api/uplink?since=<last seq> every second, so each
// poll carries only the frames that are new since the last one.

let SEEN = 0;               // highest frame seq rendered
let ROWS = [];              // newest first, mirrors the server ring buffer
const MAX_ROWS = 400;

const $ = (s) => document.querySelector(s);
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString("en-GB");
const sign = (n, d = 1) => (n >= 0 ? "+" : "") + n.toFixed(d);

function renderKpis(k) {
  $("#k-frames").textContent = k.frames ?? "–";
  $("#k-attacks").textContent = k.attacks ?? "–";
  $("#k-sources").textContent = k.sources ?? "–";
  $("#k-fcs").textContent = k.fcs_broken ?? "–";
}

function renderLink(link) {
  const el = $("#link");
  el.textContent = link.state;
  el.className = "link-state " + link.state;
  $("#link-detail").textContent = link.detail || "";
}

function renderSources(sources) {
  $("#srcs").innerHTML = sources
    .map((s) => {
      const cmds = Object.entries(s.cmds)
        .map(([c, n]) => `${c}×${n}`)
        .join(", ");
      return `<span class="chip${s.legit ? "" : " bad"}">${s.src} · ${s.count} · ${cmds}</span>`;
    })
    .join("");
}

function rowHtml(f, isNew) {
  const kind = f.fcs_broken ? `${f.what} + FCS` : f.what;
  return (
    `<tr class="${f.legit ? "" : "att"}${isNew ? " new" : ""}">` +
    `<td>${fmtTime(f.ts)}</td>` +
    `<td class="mono">${f.t_pass_s.toFixed(1)}s</td>` +
    `<td class="mono">${f.src}</td>` +
    `<td class="mono">${f.cmd}</td>` +
    `<td class="mono">${sign(f.foff_khz)}</td>` +
    `<td class="mono">${sign(f.dop_hz, 0)}</td>` +
    `<td>${kind}</td>` +
    `<td>${f.status === "sent" ? "sent" : "<b>ERR</b>"}</td>` +
    `</tr>`
  );
}

function render(fresh) {
  // fresh frames arrive oldest-first; the table is newest-first
  for (const f of fresh) ROWS.unshift(f);
  if (ROWS.length > MAX_ROWS) ROWS.length = MAX_ROWS;
  const newSeqs = new Set(fresh.map((f) => f.seq));
  $("#feed-body").innerHTML = ROWS.map((f) => rowHtml(f, newSeqs.has(f.seq))).join("");
  $("#updated").textContent = new Date().toLocaleTimeString("en-GB");
}

async function tick() {
  try {
    const r = await fetch(`/api/uplink?since=${SEEN}`);
    const s = await r.json();
    renderLink(s.link);
    renderKpis(s.kpis);
    renderSources(s.sources);
    if (s.seq < SEEN) {           // server restarted: start the list over
      SEEN = 0;
      ROWS = [];
    }
    if (s.frames.length) {
      SEEN = s.frames[s.frames.length - 1].seq;
      render(s.frames);
    } else {
      $("#updated").textContent = new Date().toLocaleTimeString("en-GB");
    }
  } catch (e) {
    renderLink({ state: "offline", detail: "server unreachable" });
  }
}

tick();
setInterval(tick, 1000);
