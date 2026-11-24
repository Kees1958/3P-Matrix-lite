// ── ui/popup.js — toolbar popup controller ────────────────────────────────────
// Renders the view model the service worker returns (MSG_GET_POPUP_STATE) and
// sends user actions back. Holds no business logic: every change round-trips
// through the service worker, which returns the fresh view model.
// All text goes into the DOM via textContent (host names are untrusted).
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { LEVEL, LEVEL_MIN, LEVEL_MAX, ICON_DIR, ICON_UI_SIZE, SEVERITY, TAMPER_RATING, POPUP_MATCHED_RULES_MAX } from "../data/constants.js";
import { fillDerivedText, levelRange, LIST_SEPARATOR } from "./derived-text.js";
import { BUILTIN_SUMMARY } from "../data/builtin-domains.js";
import { showError, releaseStatus } from "./status-line.js";

// ── Popup-only presentation constants ───────────────────────────────────────
// Colours = the shared design tokens in ui/common.css (their single source; finding 14).
const ALLOW_COLOR   = "var(--allow)";
const BLOCK_COLOR   = "var(--block)";
const NEUTRAL_COLOR = "var(--muted)";
const LOCK_ICON_ON_ACCENT = "var(--bg)";      // lock icon on the level-coloured (locked) button
const LOCK_ICON_PLAIN     = "var(--bright)";  // lock icon on the plain (unlocked) button
const SVG_NS = "http://www.w3.org/2000/svg";
const LOCK_PATH_CLOSED = "M8 11V7a4 4 0 0 1 8 0v4";
const LOCK_PATH_OPEN   = "M8 11V7a4 4 0 0 1 7.5-2";
// 5.1.3 — "This page" box texts and classes (the model says what; the words are here, once).
const RISK_TEXT = Object.freeze({ [SEVERITY.SUSPECT]: "Suspicious site", [SEVERITY.PHISHING]: "Dangerous site" });
const RISK_CLASS = Object.freeze({ [SEVERITY.SUSPECT]: "suspect", [SEVERITY.PHISHING]: "danger" });
// "This page" tamper line (owner, 2026-11-24): "<rating> tamper sign(s): <number>", and on the next line the most
// serious sign by name — one line, cut with "…" when too long (CSS .page-one-line; the full name on hover).
function tamperCountText(t) { return `${t.ratingLabel} tamper ${t.findings === 1 ? "sign" : "signs"}: ${t.findings}`; }
const LIST_JOIN = ", ";
const BLOCK_COUNT_UNKNOWN = "";              // the count could not be asked (no activeTab grant, quota): nothing shown
const SAFER_OPEN_DEFAULT = true;          // 4.2: safer-regions panel starts expanded (TLD list visible at once)
const TRACK_INSET_PX = 44;                // slider track: total horizontal inset of the fill (= popup.css .track left + right)

// ── Popup state (guarded: initialised empty, replaced wholesale per response) ─
let tab = null;            // { id, url } of the active tab
let model = null;          // last view model from the service worker
let safeOpen = SAFER_OPEN_DEFAULT;  // Safer-regions panel open
let busy = false;          // guard: ignore clicks while a request is in flight

function $(id) { return document.getElementById(id); }

function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, tabId: tab && tab.id, url: tab && tab.url, ...extra })
    .then((res) => { if (!res || !res.ok) throw new Error(res && res.error || "no response"); return res.data; });
}

async function act(type, extra, { reloadTab = false } = {}) {
  if (busy) return;
  busy = true;
  try {
    model = await send(type, extra);
    render();
    if (reloadTab && tab && model.scorable) chrome.tabs.reload(tab.id).catch(() => { /* tab closed meanwhile */ });
  } catch (e) {
    showError($("popupStatus"), e);
  } finally {
    busy = false;                                              // release on every path
  }
}

// ── Active policy bullets (fixed order: allow · level-specific · block) ─────
// 5.1.5: the protections are counted per tab (tabLines); none gets a bullet of its own. Every count comes from the view model (registry-derived) —
// never a number typed into the text (C39a).
// 4.2: levels 3–5 target 3P scripts + frames only; images/video/fonts/CSS are never blocked.
function countText(active, total) {
  return active === total ? String(total) : `${active} of ${total}`;
}

// 5.1.5 (owner): one line per Protections-page tab, a number after each (core/policy.js protectionCounts); a switched-
// off tab says "off". Switches and trigger ticks are not protections and are not counted.
const OFF_TEXT = "off";
function tabLines(m, c, withOutside) {
  const t = m.counts;
  const fw = withOutside ? ` (${countText(t.firewall.outside.active, t.firewall.outside.total)} outside safer regions)` : "";
  return [
    { c, t: `Firewall protection: ${countText(t.firewall.active, t.firewall.total)}${fw}` },
    { c: t.download.on ? c : NEUTRAL_COLOR, t: `Download protection: ${t.download.on ? t.download.active : OFF_TEXT}` },
    { c: t.scam.on ? c : NEUTRAL_COLOR, t: `Scam protection: ${t.scam.on ? t.scam.active : OFF_TEXT}` },
    { c: t.tamper.on ? c : NEUTRAL_COLOR, t: `Tamper protection: ${t.tamper.on ? `${t.tamper.signs} signs` : OFF_TEXT}` }
  ];
}

function bulletsFor(m) {
  const c = m.levelInfo[m.level - 1].color;
  // Derived from the whitelist's own categories (4.5.6: BUILTIN_SUMMARY — it used to be a typed copy).
  const builtin = { c: ALLOW_COLOR, t: `Trusted: ${BUILTIN_SUMMARY.join(LIST_SEPARATOR)}` };
  switch (m.level) {
    case LEVEL.ALLOW_ALL: return [{ c: NEUTRAL_COLOR, t: "All traffic allowed — no protections" }];
    case LEVEL.MILD: return tabLines(m, c, false);
    case LEVEL.SMART: return [
      builtin,
      { c: ALLOW_COLOR, t: `3P code from ${m.safeZone.tlds.length} safer-region TLDs allowed` },
      ...tabLines(m, c, true),
      { c: BLOCK_COLOR, t: "Other 3P scripts & frames blocked" }];
    case LEVEL.HIGH: return [
      builtin,
      { c, t: "3P code from “cdn” hosts allowed" },
      ...tabLines(m, c, false),
      { c: BLOCK_COLOR, t: "Other 3P scripts & frames blocked" }];
    default: return [
      ...tabLines(m, c, false),
      { c: BLOCK_COLOR, t: "All 3P scripts & frames blocked — no exceptions" }];
  }
}

// ── DOM builders ─────────────────────────────────────────────────────────────
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function lockSvg(closed, color) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", "22"); svg.setAttribute("height", "22"); svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none"); svg.style.stroke = color;   // style, not attribute: accepts var(--token) svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round"); svg.setAttribute("stroke-linejoin", "round"); svg.setAttribute("aria-hidden", "true");
  const rect = document.createElementNS(SVG_NS, "rect");
  rect.setAttribute("x", "4"); rect.setAttribute("y", "11"); rect.setAttribute("width", "16"); rect.setAttribute("height", "10"); rect.setAttribute("rx", "2");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", closed ? LOCK_PATH_CLOSED : LOCK_PATH_OPEN);
  svg.append(rect, path);
  return svg;
}

// ── Render ───────────────────────────────────────────────────────────────────
function render() {
  const m = model;
  if (!m) return;
  const info = m.levelInfo[m.level - 1];
  const locked = m.lockedLevel !== null;
  document.documentElement.style.setProperty("--accent", info.color);

  $("levelIcon").src = `../${ICON_DIR}/${info.icon}_${ICON_UI_SIZE}.png`;
  $("startupSelect").value = String(m.startupLevel);
  $("startupSelect").style.borderColor = m.levelInfo[m.startupLevel - 1].color;

  $("siteHost").textContent = m.host || "—";
  const zone = $("siteZone");
  const saferRelevant = m.saferRegionsRelevant;             // from the view model (core/policy.js)
  zone.hidden = !saferRelevant || !m.scorable;
  zone.className = "site-zone " + (m.inSafeZone ? "in" : "out");
  zone.textContent = !m.scorable ? "" : m.inSafeZone ? "IN SAFER REGIONS" : "OUTSIDE SAFER REGIONS";

  const lockBtn = $("lockBtn");
  lockBtn.replaceChildren(lockSvg(locked, locked ? LOCK_ICON_ON_ACCENT : LOCK_ICON_PLAIN));
  lockBtn.style.background = locked ? info.color : "var(--surface)";
  lockBtn.disabled = !m.scorable;
  const lockLabel = locked ? `Locked to level ${m.level} — click to unlock` : `Lock level ${m.level} for this site`;
  lockBtn.title = lockLabel; lockBtn.setAttribute("aria-label", lockLabel);

  $("levelNum").textContent = String(m.level);
  $("levelName").textContent = info.name;
  $("lockHint").hidden = !locked;

  // Level ticks
  $("trackFill").style.width = `calc((100% - ${TRACK_INSET_PX}px) * ${(m.level - LEVEL_MIN) / (LEVEL_MAX - LEVEL_MIN)})`;
  const ticks = [];
  for (const n of levelRange()) {
    const b = el("button", "tick");
    b.type = "button";
    b.disabled = locked;
    b.setAttribute("aria-label", `Level ${n} — ${m.levelInfo[n - 1].name}`);
    // 5.0.4: under each number its one-word name (data/constants.js LEVEL_INFO.short), so the scale explains itself.
    const now = n === m.level ? " current" : "";
    const caption = el("span", "caption");
    caption.append(el("span", "num" + now, String(n)), el("span", "short" + now, m.levelInfo[n - 1].short));
    b.append(el("span", "dot" + (now || (n < m.level ? " past" : ""))), caption);
    b.addEventListener("click", () => act(M.MSG_SET_LEVEL, { level: n }, { reloadTab: true }));
    ticks.push(b);
  }
  $("tickRow").replaceChildren(...ticks);

  // Bullets
  $("bullets").replaceChildren(...bulletsFor(m).map((b) => {
    const row = el("div", "bullet");
    const dot = el("span", "b-dot"); dot.style.background = b.c;
    row.append(dot, el("span", "b-text", b.t));
    return row;
  }));

  // Safer regions
  $("safeZone").hidden = !saferRelevant;
  $("safeTitle").textContent = `Safer regions — ${m.safeZone.tlds.length} TLDs`;
  $("safeArrow").textContent = safeOpen ? "▲" : "▼";
  $("safeToggle").setAttribute("aria-expanded", String(safeOpen));
  $("safeBody").hidden = !safeOpen;
  $("tldTags").replaceChildren(...m.safeZone.tlds.map((t) => {
    const tag = el("span", "tag", t);
    const x = el("button", "", "×"); x.type = "button"; x.setAttribute("aria-label", `Remove ${t}`);
    x.addEventListener("click", () => act(M.MSG_SET_SAFE_ZONE, { removeTld: t }));
    tag.append(x);
    return tag;
  }));

  $("matrixBtn").disabled = !m.scorable;                       // web pages only

  renderPageBox(m.page);
}

// 5.1.3 — "This page": each line only when it has something to say; the box hidden when none has.
function renderPageBox(page) {
  const risk = page && page.risk;
  const tamper = page && page.tamper;
  const continued = !!(page && page.continued);
  $("pageRisk").hidden = !risk;
  if (risk) {
    $("pageRisk").className = `page-line ${RISK_CLASS[risk.severity] || ""}`.trim();
    $("pageRiskText").textContent = RISK_TEXT[risk.severity] || "";
    $("pageRiskWhy").textContent = risk.reasons.join(LIST_JOIN);
  }
  $("pageTamper").hidden = !tamper;
  if (tamper) {
    $("pageTamper").className = `page-line page-line-row ${tamper.rating >= TAMPER_RATING.HIGH ? "danger" : "suspect"}`;
    $("pageTamperText").textContent = tamperCountText(tamper);
    $("pageTamperWorst").textContent = tamper.topLabel;
    $("pageTamperWorst").title = tamper.topLabel;
  }
  $("pageContinued").hidden = !continued;
  $("pageBox").hidden = !risk && !tamper && !continued;
}

// 5.1.3 — the firewall count, asked when the popup opens: the rules Chrome says matched in this tab (opening the popup
// grants activeTab for it), counted by the service worker (block rules only). No background counting at all.
async function renderBlockCount() {
  let text = BLOCK_COUNT_UNKNOWN;
  try {
    if (tab && model && model.scorable) {
      const info = await chrome.declarativeNetRequest.getMatchedRules({ tabId: tab.id });
      const ruleIds = (info && info.rulesMatchedInfo || []).slice(0, POPUP_MATCHED_RULES_MAX).map((x) => x.rule.ruleId);
      const n = await send(M.MSG_COUNT_FIREWALL_BLOCKS, { ruleIds });
      text = n === 0 ? "Firewall blocked nothing on this page" : `Firewall blocked ${n} ${n === 1 ? "request" : "requests"} on this page`;
    }
  } catch { /* not granted (the popup opened another way) or over Chrome's quota: no count shown */ }
  $("blockedText").textContent = text;
}

// ── Wiring ───────────────────────────────────────────────────────────────────
// Startup-level options: one per level, LEVEL_MIN … LEVEL_MAX (never typed into popup.html).
function buildStartupOptions() {
  $("startupSelect").replaceChildren(...levelRange().map((n) => {
    const o = el("option", "", String(n));
    o.value = String(n);
    return o;
  }));
}

function wire() {
  $("startupSelect").addEventListener("change", (e) => act(M.MSG_SET_STARTUP_LEVEL, { level: Number(e.target.value) }));
  $("lockBtn").addEventListener("click", () => act(M.MSG_TOGGLE_LOCK, {}, { reloadTab: true }));
  $("safeToggle").addEventListener("click", () => { safeOpen = !safeOpen; render(); });
  function addTld() {
    const v = $("tldInput").value.trim();
    if (!v) return;
    $("tldInput").value = "";
    act(M.MSG_SET_SAFE_ZONE, { addTld: v });
  }
  $("tldAdd").addEventListener("click", addTld);
  $("tldInput").addEventListener("keydown", (e) => { if (e.key === "Enter") addTld(); });
  $("tldDefault").addEventListener("click", () => act(M.MSG_SET_SAFE_ZONE, { restoreDefault: true }));
  // 4.7.0: one button for the whole Protections panel (3P Matrix 4.7.0's popup used to have this plus
  // a separate "Options" button; options_ui now points at ui/protections.html, so this still opens
  // the same registered page — just under its new name and with the protections list included).
  $("protectionsBtn").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("tamperDetailsBtn").addEventListener("click", async () => {   // 5.1.3: the page's tamper window again
    try { await send(M.MSG_SHOW_TAMPER_DETAILS); window.close(); }
    catch (e) { showError($("popupStatus"), e, "Tamper details"); }
  });
  $("matrixBtn").addEventListener("click", async () => {
    try { await send(M.MSG_OPEN_MATRIX); window.close(); }
    catch (e) { showError($("popupStatus"), e, "Show Matrix"); }
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  fillDerivedText(document);
  buildStartupOptions();
  wire();
  try {
    const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
    tab = t ? { id: t.id, url: t.url || "" } : null;
    model = await send(M.MSG_GET_POPUP_STATE);
    render();
    renderBlockCount();                                         // 5.1.3: after the first render, never in its way
  } catch (e) {
    showError($("popupStatus"), e, "Could not load");
  }
});

window.addEventListener("pagehide", releaseStatus);          // release status timers with the popup
