// ── ui/matrix.js — Show Matrix panel controller ───────────────────────────────
// Layout and interaction ported from 3P-Matrix-lite 4.0.2 ui/matrix-panel.js (4.2.1):
//   Domains connected · INTERNAL WHITELIST · LEVEL MODE · image · media · stylesheet ·
//   SCRIPT · FRAME · fetch/xhr · other · requests
// SCRIPT / FRAME show the policy's real decision for that domain (green = allow, red = block —
// replayed through the active rules by core/matrix-disposition.js). Click: not overridden → set
// the opposite as an override; overridden → clear it (back to the level's default).
// Overrides apply on every site. Polls the service worker; all text goes in via textContent.
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { LEVEL, MATRIX_POLL_MS, MATRIX_SCOPE, MATRIX_SCOPE_LABEL, MATRIX_ACTION,
         MATRIX_DURATION_MS, MATRIX_CLOSE_GRACE_MS, MATRIX_TIMER_WARN_MS, MATRIX_TAB_PARAM, DECIMAL_RADIX, LOG_PREFIX } from "../data/constants.js";
import { PROTECTION_KEY } from "../data/protections.js";
import { protectionNum } from "./derived-text.js";
import { showError, releaseStatus } from "./status-line.js";

// ── Panel-only presentation constants (one place) ────────────────────────────
// Display label per observed type (MATRIX_TYPE_LABEL values); lite's names.
const TYPE_DISPLAY = Object.freeze({ image: "image", media: "media", css: "stylesheet", script: "script",
                                     frame: "frame", xhr: "fetch/xhr", other: "other" });
const TYPES_BEFORE = Object.freeze(["image", "media", "css"]);     // plain columns left of SCRIPT/FRAME
const TYPES_AFTER  = Object.freeze(["xhr", "other"]);               // plain columns right of them
const OVERRIDE_SCOPES = Object.freeze([MATRIX_SCOPE.SCRIPT, MATRIX_SCOPE.FRAME]);
const CHECK = "✓";
const CROSS = "✕";
const DASH = "—";
const TIMER_RUNNING = "▶";
const TIMER_STOPPED = "■";
const MS_PER_SECOND = 1000;
const SECONDS_PER_MINUTE = 60;
const SECONDS_DIGITS = 2;                // "4:05"
const FILL = Object.freeze({ allow: "fill-green", block: "fill-red", green: "fill-green", grey: "fill-grey" });
// Glyph per square state (4.2.2): ✓ = allowed / on the whitelist, ✕ = blocked, none = grey or empty.
const GLYPH = Object.freeze({ allow: CHECK, block: CROSS, green: CHECK, grey: "" });
// Level note — one element, same layout at every level; only the text differs. The "Level N — "
// prefix and the protection number are derived at render time, never typed (C39a).
const LEVEL_NOTE = Object.freeze({
  [LEVEL.ALLOW_ALL]: "all third-party traffic is allowed. Script/frame overrides you set still apply.",
  [LEVEL.MILD]:      `only third-party scripts and frames from abused TLDs are blocked (protection ${protectionNum(PROTECTION_KEY.BLOCK_ABUSED_TLDS)}).`,
  [LEVEL.SMART]:    "third-party scripts and frames are blocked, except safer-region TLDs and the internal whitelist.",
  [LEVEL.HIGH]:      "third-party scripts and frames are blocked, except hosts with “cdn” in the name and the internal whitelist.",
  [LEVEL.STRICT]:    "all third-party scripts and frames are blocked, no exceptions. ALLOW overrides have no effect here."
});
const WHITELIST_TITLE = Object.freeze({
  green: (r) => `Built-in whitelist: ${r.whitelistCategory}`,
  grey:  (r) => r.whitelistApplies ? `Built-in whitelist: ${r.whitelistCategory} — overridden by a script/frame setting`
                                   : `Built-in whitelist: ${r.whitelistCategory} — not applied at this level`
});

// Column model — header and every row are built from this one list.
//   kind: domain | whitelist | mode | type (plain seen check) | status (SCRIPT/FRAME) | count
const COLUMNS = Object.freeze([
  { kind: "domain",    label: "Domains connected" },
  { kind: "whitelist", label: ["Internal", "whitelist"], title: "Informational: green = on the built-in whitelist and applied at this level; grey = overridden or not applied at this level" },
  { kind: "mode",      label: ["Level", "mode"], title: "Informational: what this level's own rules decide for this domain's scripts; grey when a script/frame setting or the built-in whitelist decides instead" },
  ...TYPES_BEFORE.map((t) => ({ kind: "type", type: t, label: TYPE_DISPLAY[t] })),
  ...OVERRIDE_SCOPES.map((sc) => ({ kind: "status", scope: sc, label: MATRIX_SCOPE_LABEL[sc].toUpperCase(),
                                   title: `Click to override this domain's ${MATRIX_SCOPE_LABEL[sc].toLowerCase()}s — click again to undo` })),
  ...TYPES_AFTER.map((t) => ({ kind: "type", type: t, label: TYPE_DISPLAY[t] })),
  { kind: "count",     label: "Requests" }
].map((c, i) => Object.freeze({ ...c, groupStart: i > 0 })));

function $(id) { return document.getElementById(id); }
const tabId = Number.parseInt(new URLSearchParams(location.search).get(MATRIX_TAB_PARAM), DECIMAL_RADIX);

// ── Guarded panel state ──────────────────────────────────────────────────────
let model = null;          // last model from the service worker
let pollTimer = null;      // released in releaseAll()
let closeTimer = null;     // fallback self-close; released in releaseAll()
let busy = false;          // one override change at a time
let closed = false;        // guard: close only once

function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, tabId, ...extra })
    .then((res) => { if (!res || !res.ok) throw new Error(res && res.error || "no response"); return res.data; });
}

function releaseAll() {
  if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; }
  if (closeTimer !== null) { clearTimeout(closeTimer); closeTimer = null; }
}

function closePanel(reasonText) {
  if (closed) return;
  closed = true;
  releaseAll();
  $("timerIcon").textContent = TIMER_STOPPED;
  $("timerDisplay").classList.add("expired");
  if (reasonText) { $("emptyState").hidden = false; $("emptySub").textContent = reasonText; }
  window.close();
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function setLabel(th, label) {
  if (Array.isArray(label)) label.forEach((line) => th.append(el("span", "th-line", line)));
  else th.textContent = label;
}

function fmtTime(ms) {
  const s = Math.ceil(Math.max(0, ms) / MS_PER_SECOND);
  return `${Math.floor(s / SECONDS_PER_MINUTE)}:${String(s % SECONDS_PER_MINUTE).padStart(SECONDS_DIGITS, "0")}`;
}

// ── Header (one row; every column is a single cell spanning the header height) ──
function buildHeader() {
  const tr = el("tr");
  for (const col of COLUMNS) {
    const th = el("th", (col.kind === "domain" ? "th-domain" : "") + (col.groupStart ? " group-start" : ""));
    setLabel(th, col.label);
    if (col.title) th.title = col.title;
    tr.append(th);
  }
  $("matrixThead").replaceChildren(tr);
}

function square(state) {
  return el("span", "mini-square" + (state ? ` filled ${FILL[state]}` : ""), state ? GLYPH[state] : "");
}

// ── Override click: not overridden → opposite of the current decision; overridden → clear ──
async function toggle(domain, scope, disposition) {
  if (busy) return;
  busy = true;
  const action = disposition.overridden ? null
    : (disposition.effective === MATRIX_ACTION.ALLOW ? MATRIX_ACTION.BLOCK : MATRIX_ACTION.ALLOW);
  try {
    model = await send(M.MSG_SET_MATRIX_RULE, { domain, scope, action });
    render();
  } catch (e) {
    showError($("mxStatus"), e);
  } finally {
    busy = false;                                         // release on every path
  }
}

function cellFor(col, row) {
  const td = el("td", col.groupStart ? "group-start" : "");
  switch (col.kind) {
    case "domain":
      td.className = "td-domain" + (col.groupStart ? " group-start" : "");
      td.textContent = row.domain;
      break;
    case "whitelist":
      td.append(square(row.whitelist === "empty" ? null : row.whitelist));
      if (WHITELIST_TITLE[row.whitelist]) td.title = WHITELIST_TITLE[row.whitelist](row);
      break;
    case "mode":
      td.append(square(row.mode));
      break;
    case "type": {
      const has = row.types.includes(col.type);
      td.append(el("span", "td-check" + (has ? "" : " empty"), has ? CHECK : DASH));
      break;
    }
    case "status": {
      const d = row[col.scope];
      if (!d) break;                                      // type never seen, no override — blank
      td.className = "td-status clickable" + (col.groupStart ? " group-start" : "");
      td.append(square(d.effective));
      const label = MATRIX_SCOPE_LABEL[col.scope];
      td.title = `${label}: ${d.effective === MATRIX_ACTION.ALLOW ? "allowed" : "blocked"}` +
                 (d.overridden ? " — your override (click to undo)" : " — level default (click to override)");
      td.setAttribute("role", "button");
      td.setAttribute("aria-label", `${label} for ${row.domain}: ${td.title}`);
      td.addEventListener("click", () => toggle(row.domain, col.scope, d));
      break;
    }
    case "count":
      td.className = "td-num" + (col.groupStart ? " group-start" : "");
      td.textContent = String(row.count);
      break;
  }
  return td;
}

function render() {
  const m = model;
  if (!m) return;
  const info = m.levelInfo[m.level - 1];
  document.documentElement.style.setProperty("--level-color", info.color);
  $("panelHost").textContent = m.host || DASH;
  const d = m.entries.length, r = m.requestCount;
  $("panelStats").textContent = `L${m.level} · ${info.name}`;
  $("mxStats").textContent = `${d} third-party domain${d === 1 ? "" : "s"} · ${r} request${r === 1 ? "" : "s"} observed`;
  const note = $("levelNote");
  note.textContent = LEVEL_NOTE[m.level] ? `Level ${m.level} — ${LEVEL_NOTE[m.level]}` : "";
  note.hidden = !note.textContent;

  const timer = $("timerDisplay");
  timer.textContent = m.observing ? fmtTime(m.remaining) : fmtTime(0);
  timer.classList.toggle("warning", m.observing && m.remaining <= MATRIX_TIMER_WARN_MS);

  const rows = m.entries.slice().sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain));
  $("entryBody").replaceChildren(...rows.map((row) => {
    const tr = el("tr");
    tr.append(...COLUMNS.map((col) => cellFor(col, row)));
    return tr;
  }));
  $("emptyState").hidden = rows.length > 0;

  if (!m.observing) { closePanel("Show Matrix session ended."); return; }
  // Re-arm the fallback from the service worker's own clock (a re-opened panel restarts it).
  if (closeTimer !== null) clearTimeout(closeTimer);
  closeTimer = setTimeout(() => closePanel("Time limit reached — session closed."), m.remaining + MATRIX_CLOSE_GRACE_MS);
}

async function poll() {
  if (closed) return;
  try { model = await send(M.MSG_GET_MATRIX_DATA); render(); }
  catch (e) { console.warn(LOG_PREFIX, "matrix poll:", e); }       // transient; the next poll retries
}

document.addEventListener("DOMContentLoaded", () => {
  buildHeader();
  $("timerIcon").textContent = TIMER_RUNNING;
  if (!Number.isInteger(tabId)) { $("emptySub").textContent = "No tab to observe — please reopen from the popup."; return; }
  $("btnReload").addEventListener("click", () => send(M.MSG_RELOAD_TAB).catch((e) => showError($("mxStatus"), e, "Not reloaded")));
  $("btnClose").addEventListener("click", async () => {
    releaseAll();
    await send(M.MSG_STOP_MATRIX).catch(() => { /* the panel closes anyway; the SW stops on its timeout */ });
    closePanel();
  });
  poll();
  pollTimer = setInterval(poll, MATRIX_POLL_MS);
  closeTimer = setTimeout(() => closePanel(), MATRIX_DURATION_MS + MATRIX_CLOSE_GRACE_MS);   // last-resort guard
});

window.addEventListener("pagehide", () => { releaseAll(); releaseStatus(); });   // release every timer with the window
