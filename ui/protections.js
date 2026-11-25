// ── ui/protections.js — Protections panel controller (4.7.0) ──────────────────
// Replaces ui/options.html + the popup's old "Protections ▼" dropdown with one full-tab page,
// three tabs: Browsing Protection (every protection except the two DOWNLOAD-mechanism ones),
// Download Protection (those two + VT key + download settings + the online-checks DNS pair, moved
// here from the old Options page), Allow whitelist (unchanged, + import/export, user request).
// 5.1.0: four tabs — + Tamper Protection (its switch, what it looks for, how it watches, exceptions, this session's findings). Rule: a
// feature with its own tab owns its protections and its settings; each tab's list comes from the registry's `tab`
// field (data/protections.js) through the view model's groups (g.tab) — no tab keeps its own list.
// Backup/Restore/Reset moved here too (footer, applies under every tab). Opened as the extension's
// options page (manifest.json options_ui, open_in_tab) and from the popup's "Protections" button.
// Every change round-trips through the service worker; every outcome — success or failure — is
// shown in that section's status line (ui/status-line.js), never left in the console only.
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { DNS_NONE, VT_JOIN_URL, VT_API_KEY_RE, FP_LEVEL_ORDER, AUTO_ALLOW_THRESHOLD_MIN,
         AUTO_ALLOW_THRESHOLD_MAX, DOWNLOAD_DEFAULTS, DOWNLOAD_WARNING_TITLE_DEFAULT,
         DOWNLOAD_WARNING_TITLE_MAX, RGB_CHANNEL_MAX, DECIMAL_RADIX,
         IMPORT_FILE_MAX_BYTES, BYTES_PER_MEBIBYTE, LEVEL } from "../data/constants.js";
import { PROTECTION_TAB, PROTECTION_GROUPS, SCAM_LIST_ORDER, protectionsInGroup } from "../data/protections.js";
import { fillDerivedText } from "./derived-text.js";
import { showStatus, showError, releaseStatus } from "./status-line.js";

// ── Settings (one place) ─────────────────────────────────────────────────────
const TAB = Object.freeze({ BROWSING: "browsing", DOWNLOAD: "download", SCAM: "scam", TAMPER: "tamper", ALLOW: "allow" });   // 5.1.3: + SCAM
const TAB_BTN_ID   = Object.freeze({ [TAB.BROWSING]: "tabBrowsing",   [TAB.DOWNLOAD]: "tabDownload",   [TAB.SCAM]: "tabScam",   [TAB.TAMPER]: "tabTamper",   [TAB.ALLOW]: "tabAllow" });
const TAB_PANEL_ID = Object.freeze({ [TAB.BROWSING]: "panelBrowsing", [TAB.DOWNLOAD]: "panelDownload", [TAB.SCAM]: "panelScam", [TAB.TAMPER]: "panelTamper", [TAB.ALLOW]: "panelAllow" });
// 5.1.0: the list container of each registry tab (data/protections.js PROTECTION_TAB).
const LIST_ID = Object.freeze({ [PROTECTION_TAB.BROWSING]: "browsingList", [PROTECTION_TAB.DOWNLOAD]: "downloadList", [PROTECTION_TAB.SCAM]: "scamList", [PROTECTION_TAB.TAMPER]: "tamperList" });
const DEFAULT_TAB = TAB.BROWSING;
const EXPORT_FILE_NAME = "3p-matrix-settings.json";
const EXPORT_MIME = "application/json";
const ALLOW_EXPORT_FILE_NAME = "3p-matrix-allow-list.txt";
const ALLOW_EXPORT_MIME = "text/plain";
const EXPORT_JSON_INDENT = 2;
const RESET_CONFIRM_TEXT = "Reset every 3P Matrix setting to its default (the VirusTotal key included)?";
const VT_KEY_SET_PLACEHOLDER = "•••••••••••••••• (a key is saved — paste a new one to replace it)";
const VT_KEY_EMPTY_PLACEHOLDER = "Paste your VT API key (64 hex characters)…";
const VT_KEY_STATUS = Object.freeze({
  SAVED:    "API key saved.",
  CLEARED:  "API key cleared.",
  EMPTY:    "please enter your API key",
  INVALID:  "invalid key — expected 64 hex characters",
  WITH_SETTINGS: "Download settings and API key saved."
});
const RGB_INPUTS = Object.freeze({ r: "colorR", g: "colorG", b: "colorB" });
const ALLOW_LIST_SEPARATOR = "\n";
const LINE_SPLIT_RE = /\r\n|\r|\n/;                                  // 5.1.3: allow-list search
// 5.1.3 (issues 3, 5) — the Tamper Protection tab's signal list: its heading, the note on a row whose protection gives
// its own warning (core/tamper-guard.js tamperView `warnsAtOnce`), and the tooltip's points text.
const TAMPER_LIST_HEAD = "Signs of tampering — points add up to the page's risk rating";
const TAMPER_WARNS_AT_ONCE = "warns at once";
function tamperPointsText(points) { return `${points} points.`; }
// 5.1.3 (owner) — on these tabs the switch the other rows depend on gets a card of its own ABOVE their group, titled
// here; while it is off the whole tab is shown off (TAB_OFF_CLASS on its panel: dependent ticks disabled and unticked,
// the explanation and lists dimmed). UI only: core/policy.js already makes every dependent protection inactive.
const SWITCH_CARD_TITLE = Object.freeze({ [PROTECTION_TAB.TAMPER]: "Tamper protection" });
// 5.1.6 (owner): tabs whose groups stand side by side (first group left, the extra one right) instead of one column.
const SIDE_BY_SIDE_TABS = Object.freeze([PROTECTION_TAB.DOWNLOAD]);
const TAB_OFF_CLASS = "tab-off";

// ── Page state (guarded: null until the first model arrives) ─────────────────
let model = null;                      // last options/protections model

function $(id) { return document.getElementById(id); }
function masterOffText(label) { return `Does nothing while “${label}” is off.`; }

function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, ...extra })
    .then((res) => { if (!res || !res.ok) throw new Error(res && res.error || "no response"); return res.data; });
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function showTab(tab) {
  for (const t of Object.values(TAB)) {
    $(TAB_BTN_ID[t]).setAttribute("aria-selected", String(t === tab));
    $(TAB_PANEL_ID[t]).hidden = t !== tab;
  }
}

// ── Protections lists (adapted from the popup's old "Protections ▼" dropdown) ─
// 5.1.0: one list per registry tab (LIST_ID) — Browsing, Download (warnRiskyDownloads, blockRiskyDownloads) and Tamper Guard.
function buildProtGroup(g) {
  const wrap = document.createElement("div"); wrap.className = "prot-group";
  const head = document.createElement("div"); head.className = "prot-group-head";
  const title = document.createElement("span"); title.textContent = g.title;
  const from = document.createElement("span"); from.className = "from"; from.textContent = `from L${g.fromLevel}`;
  head.append(title, from);
  wrap.append(head);
  g.items.forEach((it) => {
    const lab = document.createElement("label"); lab.className = "prot-item" + (it.enabled ? "" : " off") + (it.masterOff ? " master-off" : "");
    // 5.1.3: its master is off → shown off and not clickable; the stored tick is kept and shows again with the master.
    const cb = document.createElement("input"); cb.type = "checkbox"; cb.checked = it.enabled && !it.masterOff;
    cb.disabled = !!it.masterOff;
    cb.addEventListener("change", () => setProtection(it.key, cb.checked));
    // 5.1.0: an unnumbered row (Download / Tamper Protection tab) gets no number column at all — no empty gap.
    const num = it.num ? Object.assign(document.createElement("span"), { className: "p-num", textContent: String(it.num) }) : null;
    const text = document.createElement("span"); text.className = "p-label"; text.textContent = it.label;
    if (it.masterOff) {                                              // 5.1.0: its master protection (`requires`) is off
      const why = document.createElement("span"); why.className = "p-why"; why.textContent = masterOffText(it.masterLabel);
      text.append(why);
    }
    lab.append(...(num ? [cb, num, text] : [cb, text]));
    // Hover/focus tooltip with what this protection does (data/protections.js' own description field —
    // never a copy typed here, C39a). CSS caps it to 3 lines (-webkit-line-clamp) as a guard against any
    // future description running long.
    if (it.description) {
      const tip = document.createElement("span"); tip.className = "p-tip"; tip.textContent = it.description;
      tip.setAttribute("role", "tooltip");
      lab.append(tip);
    }
    wrap.append(lab);
  });
  return wrap;
}

// 5.1.3 (owner, 2026-11-24): ONE column — every group of the tab under the previous one, in PROTECTION_GROUPS' own
// order (data/protections.js); the 4.7.0 two-column split (first group left, the rest right) is gone.
// 5.1.3: the switch of a SWITCH_CARD_TITLE tab — the row the tab's other rows name as their master — in its own group.
function splitSwitch(groups, tab) {
  if (!SWITCH_CARD_TITLE[tab] || !groups.length) return groups;
  const masters = new Set(groups.flatMap((g) => g.items).map((it) => it.masterLabel).filter(Boolean));
  const first = groups[0];
  const sw = first.items.filter((it) => masters.has(it.label));
  if (!sw.length) return groups;
  const rest = first.items.filter((it) => !masters.has(it.label));
  const switchGroup = { ...first, title: SWITCH_CARD_TITLE[tab], items: sw };
  return [switchGroup, ...(rest.length ? [{ ...first, items: rest }] : []), ...groups.slice(1)];
}

function renderProtList(container, tab) {
  const groups = splitSwitch(model.groups.filter((g) => g.tab === tab && g.items.length), tab);
  const panel = container.closest(".tab-panel");
  if (panel && SWITCH_CARD_TITLE[tab]) panel.classList.toggle(TAB_OFF_CLASS, groups.some((g) => g.items.some((it) => it.masterOff)));
  if (!groups.length) {
    container.replaceChildren(Object.assign(document.createElement("p"), { className: "prot-empty", textContent: "Nothing in this group yet." }));
    return;
  }
  const col = document.createElement("div");
  col.className = SIDE_BY_SIDE_TABS.includes(tab) ? "prot-col prot-row" : "prot-col";
  groups.forEach((g) => col.append(buildProtGroup(g)));
  container.replaceChildren(col);
}

function renderProtLists() {
  for (const [tab, id] of Object.entries(LIST_ID)) renderProtList($(id), tab);
}

// ── Tamper Protection tab (5.1.3): the signs of tampering, plain, most points first (core/tamper-guard.js tamperView);
// the explanation and the points are the row's hover/focus tooltip — no severity headings. ──
function tamperRow(r) {
  const item = document.createElement("div"); item.className = "prot-item tg-item"; item.tabIndex = 0;
  const label = document.createElement("span"); label.className = "p-label"; label.textContent = r.label;
  if (r.warnsAtOnce) {                                             // issue 3: its own warning comes at once
    const note = document.createElement("span"); note.className = "tg-at-once"; note.textContent = TAMPER_WARNS_AT_ONCE;
    label.append(note);
  }
  const tip = document.createElement("span"); tip.className = "p-tip"; tip.setAttribute("role", "tooltip");
  tip.textContent = `${r.description} ${tamperPointsText(r.points)}`;
  item.append(label, tip);
  return item;
}

// ── Scam protection tab (5.1.3): the rows under the switch, plain, the meaning on hover — like the Tamper tab, but
// without severity groups (each scam protection acts on its own). Read straight from the registry (C21). ──
function renderScamRules() {
  const rows = PROTECTION_GROUPS.filter((g) => g.tab === PROTECTION_TAB.SCAM).flatMap(protectionsInGroup)
    .filter((p) => p.switchable === false);
  // 5.1.6: SCAM_LIST_ORDER decides the order; a row not in it (guard) comes after, in registry order.
  function rank(p) { const i = SCAM_LIST_ORDER.indexOf(p.key); return i < 0 ? SCAM_LIST_ORDER.length : i; }
  rows.sort((a, b) => rank(a) - rank(b));
  const box = document.createElement("div"); box.className = "prot-group";
  for (const p of rows) {
    const item = document.createElement("div"); item.className = "prot-item tg-item"; item.tabIndex = 0;
    const label = document.createElement("span"); label.className = "p-label"; label.textContent = p.label;
    const tip = document.createElement("span"); tip.className = "p-tip"; tip.setAttribute("role", "tooltip");
    tip.textContent = p.fromLevel > LEVEL.MILD ? `${p.description} From level ${p.fromLevel}, outside safer regions.` : p.description;
    item.append(label, tip);
    box.append(item);
  }
  $("scRules").replaceChildren(box);
}

function renderTamper(view) {
  const box = document.createElement("div"); box.className = "prot-group";
  const head = document.createElement("div"); head.className = "prot-group-head"; head.textContent = TAMPER_LIST_HEAD;
  box.append(head, ...view.rules.map(tamperRow));                 // the view's order: most points first
  $("tgRules").replaceChildren(box);
}

async function loadTamper() {
  try { renderTamper(await send(M.MSG_GET_TAMPER_VIEW)); }
  catch (e) { showError($("tgStatus"), e, "Could not load tamper protection"); }
}


async function setProtection(key, enabled) {
  try {
    const res = await send(M.MSG_SET_PROTECTION, { key, enabled });   // popupModel's shape (no tabId/url here) — only .groups matters
    model.groups = res.groups;
    renderProtLists();
  } catch (e) {
    renderProtLists();                                               // snap the checkbox back to the saved state
    showError($("dlStatus"), e, "Could not change that protection");
  }
}

// ── VT-key status line ───────────────────────────────────────────────────────
function renderVtLine() {
  const set = model.downloads.vtKeySet;
  $("vtLineSet").hidden = !set;
  $("vtLineUnset").hidden = set;
}

function render() {
  if (!model) return;
  renderProtLists();
  renderScamRules();                                               // 5.1.3
  renderVtLine();
  fillSelect($("dnsFirst"), model.dns.first);
  fillSelect($("dnsSecond"), model.dns.second);
  $("allowList").value = model.allowList;
  renderDownloads();
}

function fillSelect(sel, value) {
  sel.replaceChildren(...model.providers.map((p) => {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = p.host ? `${p.label} — ${p.host}` : p.label;
    o.selected = p.id === value;
    return o;
  }));
}

// ── Download protection ──────────────────────────────────────────────────────
function buildDownloadControls() {
  $("autoAllowThreshold").min = String(AUTO_ALLOW_THRESHOLD_MIN);
  $("autoAllowThreshold").max = String(AUTO_ALLOW_THRESHOLD_MAX);
  $("fpSlider").min = "0";
  $("fpSlider").max = String(FP_LEVEL_ORDER.length - 1);
  $("fpSlider").step = "1";
  $("fpLabels").replaceChildren(...FP_LEVEL_ORDER.map((lvl) => { const s = document.createElement("span"); s.textContent = lvl; return s; }));
  for (const id of Object.values(RGB_INPUTS)) { $(id).min = "0"; $(id).max = String(RGB_CHANNEL_MAX); }
  $("warningTitle").maxLength = DOWNLOAD_WARNING_TITLE_MAX;
  $("warningTitle").placeholder = DOWNLOAD_WARNING_TITLE_DEFAULT;
}

// 4.7.5: the per-level detail line (window threshold, via WarnPolicy) was dropped from the UI — the
// fpHint element it wrote into no longer exists in protections.html. showFpLevel() now only toggles
// which FP_LEVEL_ORDER label is marked active; FP_LEVEL_HINT/WarnPolicy/formatScore are unused here now.
function showFpLevel(index) {
  [...$("fpLabels").children].forEach((s, i) => s.classList.toggle("active", i === index));
}

function showColorPreview() {
  const v = readColor();
  $("colorPreview").style.backgroundColor = `rgb(${v.r}, ${v.g}, ${v.b})`;
}

function isCustomLook(d) {
  const def = DOWNLOAD_DEFAULTS.warningColor;
  return d.warningTitle !== "" || Object.keys(RGB_INPUTS).some((ch) => d.warningColor[ch] !== def[ch]);
}

function fillLook(color, title) {
  for (const [ch, id] of Object.entries(RGB_INPUTS)) $(id).value = String(color[ch]);
  $("warningTitle").value = title;
  showColorPreview();
}

function renderDownloads() {
  const d = model.downloads;
  $("vtApiKeyInput").value = "";
  $("vtApiKeyInput").placeholder = d.vtKeySet ? VT_KEY_SET_PLACEHOLDER : VT_KEY_EMPTY_PLACEHOLDER;
  $("silentWhenInconclusive").checked = d.silentWhenInconclusive;
  $("autoAllow").checked = d.autoAllow;
  $("autoAllowThreshold").value = String(d.autoAllowThreshold);
  $("autoAllowRow").hidden = !d.autoAllow;
  const fpIndex = Math.max(0, FP_LEVEL_ORDER.indexOf(d.fpReductionLevel));
  $("fpSlider").value = String(fpIndex);
  showFpLevel(fpIndex);
  $("trustAppStores").checked = d.trustAppStores;                // 5.1.3
  const custom = isCustomLook(d);
  $("personalize").checked = custom;
  $("personalizeBox").hidden = !custom;
  fillLook(d.warningColor, d.warningTitle);
}

function readColor() {
  const out = {};
  for (const [ch, id] of Object.entries(RGB_INPUTS)) {
    const n = Number.parseInt($(id).value, DECIMAL_RADIX);
    out[ch] = Number.isInteger(n) ? Math.min(RGB_CHANNEL_MAX, Math.max(0, n)) : DOWNLOAD_DEFAULTS.warningColor[ch];
  }
  return out;
}

// The form as a settings patch, or an error text when an input is invalid (nothing is sent then).
function readDownloadForm() {
  const personalize = $("personalize").checked;
  const threshold = Number.parseInt($("autoAllowThreshold").value, DECIMAL_RADIX);
  return {
    settings: {
      // vtEnabled is set solely by saveVtKey()/MSG_SET_VT_KEY now — not part of this form's patch.
      silentWhenInconclusive: $("silentWhenInconclusive").checked,
      autoAllow: $("autoAllow").checked,
      autoAllowThreshold: Number.isInteger(threshold)
        ? Math.min(AUTO_ALLOW_THRESHOLD_MAX, Math.max(AUTO_ALLOW_THRESHOLD_MIN, threshold))
        : DOWNLOAD_DEFAULTS.autoAllowThreshold,
      fpReductionLevel: FP_LEVEL_ORDER[Number.parseInt($("fpSlider").value, DECIMAL_RADIX)] || DOWNLOAD_DEFAULTS.fpReductionLevel,
      trustAppStores: $("trustAppStores").checked,                // 5.1.3 (domains: the allow list)
      // Personalize unticked = back to the defaults (DownloadSentinel: stale hidden values are never saved).
      warningColor: personalize ? readColor() : { ...DOWNLOAD_DEFAULTS.warningColor },
      warningTitle: personalize ? $("warningTitle").value.trim() : DOWNLOAD_DEFAULTS.warningTitle
    }
  };
}

async function saveDownloads() {
  const form = readDownloadForm();
  if (form.error) { showError($("dlStatus"), new Error(form.error)); return; }
  try {
    const typedKey = await saveTypedVtKey();                  // 4.4.1: a typed key is never silently dropped
    if (typedKey === VT_TYPED.INVALID) return;                // keep the field as typed so it can be corrected
    model = await send(M.MSG_SET_DOWNLOAD_SETTINGS, { settings: form.settings });
    render();
    showStatus($("dlStatus"), typedKey === VT_TYPED.SAVED ? VT_KEY_STATUS.WITH_SETTINGS : "Download settings saved.");
  } catch (e) { showError($("dlStatus"), e); }
}

async function saveVtKey(clear) {
  const key = clear ? "" : $("vtApiKeyInput").value.trim();
  if (!clear && !key) { showError($("vtKeyStatus"), new Error(VT_KEY_STATUS.EMPTY)); return; }
  if (!clear && !VT_API_KEY_RE.test(key)) { showError($("vtKeyStatus"), new Error(VT_KEY_STATUS.INVALID)); return; }
  try {
    model = await send(M.MSG_SET_VT_KEY, { key });
    render();
    showStatus($("vtKeyStatus"), clear ? VT_KEY_STATUS.CLEARED : VT_KEY_STATUS.SAVED);
  } catch (e) { showError($("vtKeyStatus"), e); }
}

// 4.4.1 — the key field has its own message (MSG_SET_VT_KEY: a key can never be set through the settings
// form). The Download card's own Save saves a typed key too, so pressing it never silently drops it.
const VT_TYPED = Object.freeze({ SAVED: "saved", NONE: "none", INVALID: "invalid" });
async function saveTypedVtKey() {
  const key = $("vtApiKeyInput").value.trim();
  if (!key) return VT_TYPED.NONE;
  if (!VT_API_KEY_RE.test(key)) { showError($("vtKeyStatus"), new Error(VT_KEY_STATUS.INVALID)); return VT_TYPED.INVALID; }
  model = await send(M.MSG_SET_VT_KEY, { key });
  return VT_TYPED.SAVED;
}

// 4.7.2: saveVtEnabled() / the vtEnabled checkbox were removed as redundant — saveVtKey() below already
// turns the check on when a key is saved and off when it's cleared (core/download-settings.js setVtKey()).

function openVtJoin(e) { e.preventDefault(); chrome.tabs.create({ url: VT_JOIN_URL }); }

function bindDownloadControls() {
  $("vtKeySave").addEventListener("click", () => saveVtKey(false));
  $("vtKeyClear").addEventListener("click", () => saveVtKey(true));
  $("vtApiKeyInput").addEventListener("keydown", (e) => { if (e.key === "Enter") saveVtKey(false); });
  $("vtJoinLink").addEventListener("click", openVtJoin);
  $("vtJoinLink2").addEventListener("click", openVtJoin);
  $("autoAllow").addEventListener("change", () => { $("autoAllowRow").hidden = !$("autoAllow").checked; });
  $("fpSlider").addEventListener("input", () => showFpLevel(Number.parseInt($("fpSlider").value, DECIMAL_RADIX)));
  for (const id of Object.values(RGB_INPUTS)) $(id).addEventListener("input", showColorPreview);
  $("personalize").addEventListener("change", () => {
    const on = $("personalize").checked;
    $("personalizeBox").hidden = !on;
    if (!on) fillLook(DOWNLOAD_DEFAULTS.warningColor, DOWNLOAD_DEFAULTS.warningTitle);   // visibly back to defaults
  });
  $("dlSave").addEventListener("click", saveDownloads);
  $("dlRevert").addEventListener("click", () => { if (model) renderDownloads(); });
}

async function saveDns() {
  const wantedSecond = $("dnsSecond").value;
  try {
    model = await send(M.MSG_SET_DNS, { first: $("dnsFirst").value, second: wantedSecond });
    render();
    const cleared = model.dns.second === DNS_NONE && wantedSecond !== DNS_NONE;
    showStatus($("dnsStatus"), cleared ? "Second check cleared — it was the same as the first." : "Saved.");
  } catch (e) { showError($("dnsStatus"), e); }
}

// ── Allow whitelist ───────────────────────────────────────────────────────────
// 5.1.3 — search, like uBlock's "My rules": the lines that contain the search text (case-insensitive) are shown
// under the field, and "Delete all for this domain" removes exactly those lines from the textarea. Nothing is saved
// until Save (Revert still works). The textarea stays the editor; the check happens in the service worker on Save.
function allowMatches() {
  const q = $("allowSearch").value.trim().toLowerCase();
  if (!q) return { q, lines: [] };
  return { q, lines: $("allowList").value.split(LINE_SPLIT_RE).filter((l) => l.toLowerCase().includes(q)) };
}
function showAllowMatches() {
  const { q, lines } = allowMatches();
  $("allowMatches").hidden = !lines.length;
  $("allowMatches").textContent = lines.join(ALLOW_LIST_SEPARATOR);
  $("allowDeleteMatches").disabled = !lines.length;
  $("allowMatchCount").textContent = q ? `${lines.length} line(s)` : "";
}
function deleteAllowMatches() {
  const { lines } = allowMatches();
  if (!lines.length) return;
  const drop = new Set(lines);
  $("allowList").value = $("allowList").value.split(LINE_SPLIT_RE).filter((l) => !drop.has(l)).join(ALLOW_LIST_SEPARATOR);
  showAllowMatches();
  showStatus($("allowStatus"), `${lines.length} line(s) removed — click Save to apply, or Revert.`);
}

async function saveAllowList() {
  try {
    model = await send(M.MSG_SET_ALLOW_LIST, { text: $("allowList").value });
    render();
    showStatus($("allowStatus"), "Allow list saved.");
  } catch (e) { showError($("allowStatus"), e); }
}

// 4.7.0 (user request) — plain text, one domain per line (the textarea's own format): Export downloads
// the CURRENTLY SAVED list; Import only fills the textarea (Save still commits it, same Save/Revert
// workflow as everything else here — nothing is applied just by picking a file).
function exportAllowList() {
  const url = URL.createObjectURL(new Blob([model.allowList], { type: ALLOW_EXPORT_MIME }));
  const a = document.createElement("a");
  a.href = url; a.download = ALLOW_EXPORT_FILE_NAME; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  showStatus($("allowStatus"), "Allow list saved to a file.");
}

// 5.0.7 (C50): the one reader both import paths use — the size is checked BEFORE the file is read or parsed.
async function readImportFile(file) {
  if (file.size > IMPORT_FILE_MAX_BYTES) {
    throw new Error(`file too large (over ${IMPORT_FILE_MAX_BYTES / BYTES_PER_MEBIBYTE} MB) — not a 3P Matrix file`);
  }
  return file.text();
}

async function importAllowList(e) {
  const file = e.target.files && e.target.files[0];
  e.target.value = "";                                      // allow choosing the same file again
  if (!file) return;
  try {
    const text = await readImportFile(file);
    $("allowList").value = text.split(/\r\n|\r|\n/).map((l) => l.trim()).filter(Boolean).join(ALLOW_LIST_SEPARATOR);
    showStatus($("allowStatus"), "Loaded from file — click Save to apply.");
  } catch (err) { showError($("allowStatus"), err, "Could not read that file"); }
}

// ── Backup / Restore / Reset (footer, every tab) ─────────────────────────────
async function exportSettings() {
  let url = null;
  try {
    const data = await send(M.MSG_EXPORT_SETTINGS);
    url = URL.createObjectURL(new Blob([JSON.stringify(data.file, null, EXPORT_JSON_INDENT)], { type: EXPORT_MIME }));
    const a = document.createElement("a");
    a.href = url; a.download = EXPORT_FILE_NAME; a.click();
    showStatus($("ioStatus"), `Saved: ${data.summary}`);
  } catch (e) {
    showError($("ioStatus"), e, "Not saved");
  } finally {
    if (url) setTimeout(() => URL.revokeObjectURL(url), 0);    // release the blob on every path
  }
}

async function importSettings(e) {
  const file = e.target.files && e.target.files[0];
  e.target.value = "";                                      // allow choosing the same file again
  if (!file) return;
  try {
    model = await send(M.MSG_IMPORT_SETTINGS, { settings: JSON.parse(await readImportFile(file)) });
    render();
    loadTamper();
    showStatus($("ioStatus"), `Restored: ${model.summary}`);
  } catch (err) { showError($("ioStatus"), err, "Not restored"); }
}

async function resetSettings() {
  if (!confirm(RESET_CONFIRM_TEXT)) return;
  try {
    model = await send(M.MSG_RESET_SETTINGS);
    render();
    loadTamper();
    showStatus($("ioStatus"), "All settings reset.");
  } catch (e) { showError($("ioStatus"), e, "Not reset"); }
}

document.addEventListener("DOMContentLoaded", async () => {
  fillDerivedText(document);
  buildDownloadControls();
  bindDownloadControls();
  for (const t of Object.values(TAB)) $(TAB_BTN_ID[t]).addEventListener("click", () => showTab(t));
  $(TAB_BTN_ID[TAB.TAMPER]).addEventListener("click", loadTamper);   // fresh findings each time the tab is opened
  $("dnsFirst").addEventListener("change", saveDns);
  $("dnsSecond").addEventListener("change", saveDns);
  $("allowSave").addEventListener("click", saveAllowList);
  $("allowRevert").addEventListener("click", () => { if (model) $("allowList").value = model.allowList; showAllowMatches(); });
  $("allowSearch").addEventListener("input", showAllowMatches);                 // 5.1.3
  $("allowList").addEventListener("input", showAllowMatches);
  $("allowDeleteMatches").addEventListener("click", deleteAllowMatches);
  $("allowExport").addEventListener("click", exportAllowList);
  $("allowImport").addEventListener("click", () => $("allowImportFile").click());
  $("allowImportFile").addEventListener("change", importAllowList);
  $("exportAll").addEventListener("click", exportSettings);
  $("importAll").addEventListener("click", () => $("importFile").click());
  $("importFile").addEventListener("change", importSettings);
  $("resetAll").addEventListener("click", resetSettings);
  showTab(DEFAULT_TAB);
  try {
    model = await send(M.MSG_GET_OPTIONS);
    render();
  } catch (e) { showError($("dnsStatus"), e, "Could not load the settings"); }
  loadTamper();
});

window.addEventListener("pagehide", releaseStatus);          // release status timers with the page
