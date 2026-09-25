"use strict";
// Database page: list / edit / delete packets, reset the whole store.
// Talks to hny_server.py: GET /api/packets, POST /api/packet/<id>,
// DELETE /api/packet/<id>, POST /api/reset.

const $ = (s) => document.querySelector(s);
const fmtTime = (ts) => new Date(ts * 1000).toLocaleString("en-GB");

// column key, editable?  (order must match db.html thead)
const COLS = [
  ["src", true], ["cmd", true],
  ["freq_dev_khz", true], ["dop_hz", true], ["rssi", true],
  ["crc_ok", true], ["gap_s", true],
  ["score", true], ["fuzzy", true], ["cls", true],
  ["flagged", true], ["conf", true], ["fp", true],
];
const NUM = new Set(["freq_dev_khz", "dop_hz", "rssi", "crc_ok", "gap_s",
                     "score", "fuzzy", "flagged", "conf"]);

let ROWS = [];
let editing = null; // packet id currently in edit mode

function cellText(r, k) {
  if (NUM.has(k)) return typeof r[k] === "number" ? String(r[k]) : String(r[k] ?? "");
  return String(r[k] ?? "");
}

function render() {
  const b = $("#db-body");
  b.innerHTML = "";
  $("#count").textContent = ROWS.length;
  $("#empty").hidden = ROWS.length > 0;

  for (const r of ROWS) {
    const tr = document.createElement("tr");
    if (r.flagged) tr.className = "flag";
    const ed = editing === r.id;

    let html = `<td>${r.id}</td><td>${fmtTime(r.ts)}</td>`;
    for (const [k] of COLS) {
      html += ed
        ? `<td><input class="ed" data-k="${k}" value="${cellText(r, k).replace(/"/g, "&quot;")}"></td>`
        : `<td>${cellText(r, k)}</td>`;
    }
    html += ed
      ? `<td class="ops"><button class="btn ok" data-act="save">Save</button>` +
        `<button class="btn" data-act="cancel">Cancel</button></td>`
      : `<td class="ops"><button class="btn" data-act="edit">Edit</button>` +
        `<button class="btn danger" data-act="del">Delete</button></td>`;
    tr.innerHTML = html;

    tr.querySelectorAll("button").forEach((btn) => {
      btn.onclick = () => onAction(btn.dataset.act, r, tr);
    });
    b.appendChild(tr);
  }
}

async function onAction(act, r, tr) {
  if (act === "edit") { editing = r.id; render(); return; }
  if (act === "cancel") { editing = null; render(); return; }
  if (act === "save") {
    const fields = {};
    tr.querySelectorAll("input.ed").forEach((inp) => {
      const k = inp.dataset.k;
      fields[k] = NUM.has(k) ? Number(inp.value) : inp.value;
    });
    const res = await fetch(`/api/packet/${r.id}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(fields),
    }).then((x) => x.json());
    if (!res.ok) alert("Write failed: " + (res.err || res.ok));
    editing = null;
    load();
    return;
  }
  if (act === "del") {
    if (!confirm(`Delete record #${r.id} (${r.src} / ${r.cmd})?`)) return;
    await fetch(`/api/packet/${r.id}`, { method: "DELETE" });
    load();
  }
}

async function load() {
  ROWS = await fetch("/api/packets").then((x) => x.json());
  render();
}

$("#reset").onclick = async () => {
  if (!confirm(`Delete all ${ROWS.length} records? This cannot be undone.`)) return;
  if (!confirm("Are you sure? bench_cti.db will be emptied completely.")) return;
  await fetch("/api/reset", { method: "POST" });
  editing = null;
  load();
};

load();
