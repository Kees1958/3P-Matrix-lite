// ── ui/download-warning.js — warnRiskyDownloads warning page controller ───────────────
// Port of DownloadSentinel 3.2.0 pages/warning/WarningPage.js (C21): same sections, same texts, same
// colour thresholds (DS SCORING_CONFIG). The service worker has already waited for every check
// before opening this window (core/download-guard.js), so the page asks once and renders once.
//
// 3P Matrix differences: the download id is read by the service worker from this page's own URL
// (C28 — the page never sends it); every text goes in via textContent; risk colours are CSS classes;
// action failures show in the status line. (DS 3.3.0 repurposed its old "re-submit to VirusTotal" push
// channel for the late-verdict update below; 3P Matrix uses its own MSG_DOWNLOAD_VT_UPDATE for it.)
// Without a VirusTotal key the VirusTotal box says so in two lines — "Reputation lookup at VirusTotal skipped"
// + a "Request a free (no cost) key" link (DownloadSentinel 3.3.0, item 3; 4.3.0–4.3.3 hid the box).
// A VirusTotal verdict that arrives after the first timeout is pushed in live (MSG_DOWNLOAD_VT_UPDATE,
// DS 3.3.0 item 16) and the page re-renders in place.
//
// State owned (page lifetime): lastVt / lastHost (latest record parts, for the VT button and the
// re-render), busy (one button action at a time). Released with the page.
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { LOG_PREFIX, VT_JOIN_URL, DOWNLOAD_ID_PARAM, DECIMAL_RADIX, VT_GUI_URL_PREFIX, VT_GUI_URL_SUFFIX, VT_GUI_HOME_URL, HYBRID_ANALYSIS_URL, FP_LEVEL,
         DOWNLOAD_WARNING_TITLE_DEFAULT } from "../data/constants.js";
import { SCORING_CONFIG } from "../lib/downloadsentinel/protection/ScoringEngineV2.js";
import { UrlUtils } from "../lib/downloadsentinel/util/UrlUtils.js";
import { showError, releaseStatus } from "./status-line.js";

// ── Settings (one place) ─────────────────────────────────────────────────────
const SCORE_MIN = -100, SCORE_MAX = 100;           // DownloadSentinel's combined score range (−100 … +100)
const LABEL_MAX = 200;                             // longest label shown (DownloadSentinel sanitizeLabel)
// Keep printable ASCII + Latin-1/Extended-A/B, and (4.4.0, DS 3.5.0) typographic dashes U+2010–2015, quotes
// U+2018–201F, ellipsis U+2026, arrow U+2192 — the em dash in "was hidden — no extension" used to be deleted.
// Bidi/override controls (U+202A–202E, U+2066–2069) and everything else are still stripped.
const PRINTABLE_RE = /[^ -~À-ɏ‐-―‘-‟…→]/g;
const URL_CUT_RE = /[?#].*$/;                      // "Downloaded from" shows the URL without query/fragment
const DNS_STATUS = Object.freeze({ BLOCKED: "BLOCKED", ALLOWED: "ALLOWED", SKIPPED: "SKIPPED" });   // DS DnsThreatProtection
const DNS_SOURCE = "DnsThreat";                    // breakdown rows already shown as DNS lines
const RDAP_SOURCE = "RDAP";
// 4.4.0 (DS 3.5.0 DeliveryContext): explained route quirks (row.explained, score 0) and the established-site
// credit (score > 0) are listed with their own look; other zero rows stay hidden.
const ROW_CLASS = Object.freeze({ EXPLAINED: "dw-explained", CREDIT: "dw-credit" });
// DnsThreatProtection UNKNOWN_REASON code → line text (DownloadSentinel's table, provider label prefixed).
const DNS_UNKNOWN_TEXT = Object.freeze({
  NO_THREAT_DATA: "no threat-intel data for this host",
  REQUEST_FAILED: "lookup failed (service error)",
  NXDOMAIN:       "domain name does not exist (NXDOMAIN)",
  NO_ANSWER:      "returned no DNS records for this host",
  TIMEOUT:        "lookup timed out",
  // 4.3.7 (DS 3.3.1): kept in sync with DS's table; never emitted in 3P Matrix (<all_urls> covers every provider).
  PERMISSION_MISSING: "not checked — permission not granted",
  ERROR:          "lookup failed (network error)"
});
const DNS_UNKNOWN_FALLBACK = "could not be verified";
const RISK = Object.freeze({ SAFE: "risk-safe", QUESTIONABLE: "risk-questionable", SUSPICIOUS: "risk-suspicious",
                             MALICIOUS: "risk-malicious", UNKNOWN: "risk-unknown" });
const RISK_CLASSES = Object.freeze(Object.values(RISK));
const VT_RATING_TEXT = Object.freeze({
  [RISK.SAFE]:         "VirusTotal rates it currently as probably safe",
  [RISK.QUESTIONABLE]: "VirusTotal rates it currently as probably inconclusive",
  [RISK.SUSPICIOUS]:   "VirusTotal rates it currently as probably suspicious",
  [RISK.MALICIOUS]:    "VirusTotal rates it currently as probably malicious"
});
const DISCLAIMER = Object.freeze({
  VT_UNKNOWN: "Accept conditions, ignore e-mail requirement and select QUICK SCAN for free hybrid analysis at METADEFENDER and CROWDSTRIKE, before opening the downloaded file!"
});
const VT_BUTTON = Object.freeze({ VT: "Check download at VT", HYBRID: "Check download at Hybrid Analysis" });
const GONE_TEXT = "Download no longer active — you can close this window.";
const NO_HEURISTIC_SIGNALS = "Heuristics found no alarming signals";
const BUTTON_IDS = Object.freeze(["btnOk", "btnVt"]);

// ── Page state ───────────────────────────────────────────────────────────────
let lastRecord = null;
let busy = false;

function $(id) { return document.getElementById(id); }

function sanitizeLabel(str) {
  return typeof str === "string" ? str.replace(PRINTABLE_RE, "").slice(0, LABEL_MAX) : "";
}

function riskOf(score) {
  if (typeof score !== "number") return RISK.UNKNOWN;
  if (score >= SCORING_CONFIG.THRESHOLD_SAFE) return RISK.SAFE;
  if (score >= SCORING_CONFIG.THRESHOLD_QUESTIONABLE) return RISK.QUESTIONABLE;
  if (score >= SCORING_CONFIG.THRESHOLD_SUSPICIOUS) return RISK.SUSPICIOUS;
  return RISK.MALICIOUS;
}

// DownloadSentinel classification text ("Probably Malicious" …) → the same risk class.
function riskOfClassification(c) {
  if (!c) return RISK.UNKNOWN;
  if (c.includes("Malicious")) return RISK.MALICIOUS;
  if (c.includes("Suspicious")) return RISK.SUSPICIOUS;
  if (c.includes("Inconclusive") || c.includes("Questionable")) return RISK.QUESTIONABLE;
  if (c.includes("Safe")) return RISK.SAFE;
  return RISK.UNKNOWN;
}

function setRisk(el, risk) { el.classList.remove(...RISK_CLASSES); el.classList.add(risk); }
function signed(score) { return `${score >= 0 ? "+" : ""}${score}%`; }
function clampScore(n) { return Math.max(SCORE_MIN, Math.min(SCORE_MAX, n)); }
function li(text, cls) { const e = document.createElement("li"); e.textContent = text; if (cls) e.className = cls; return e; }
function vtKnown(r) { return typeof r.vtScore === "number"; }
// 5.0.4 (DS 3.5.6) — the host verdict that was used (VirusTotal unknown → heuristics only); older records: hostResult.
function hostOf(r) { return r.hostVerdict ?? r.hostResult ?? null; }
function hostScoreOf(r) { const h = hostOf(r); return h && typeof h.score === "number" ? h.score : null; }

// ── Look (Options → Personalize) ─────────────────────────────────────────────
function applyLook(look) {
  document.documentElement.style.setProperty("--dw-page", `rgb(${look.color.r}, ${look.color.g}, ${look.color.b})`);
  $("warningTitle").textContent = look.title;
  document.title = `3P Matrix — ${look.title}`;
}

// ── Disclaimer + VT button text (what actually ran) ──────────────────────────
function renderDisclaimer(r) {
  let text = "", button = VT_BUTTON.VT;           // VirusTotal answered: the boxes say it all (4.3.1: no line)
  if (r.vtApiKeySet && !vtKnown(r)) { text = DISCLAIMER.VT_UNKNOWN; button = VT_BUTTON.HYBRID; }
  $("disclaimerText").textContent = text;
  $("disclaimerText").hidden = !text;
  $("btnVt").textContent = button;
}

// ── Scores ───────────────────────────────────────────────────────────────────
function renderScores(r) {
  const vt = vtKnown(r) ? r.vtScore : null;
  const host = hostScoreOf(r);
  if (vt === null && host === null) { $("worstScoreBox").hidden = true; return; }
  const combined = clampScore((vt ?? 0) + (host ?? 0));
  $("worstScoreBox").hidden = false;
  const positive = combined >= 0;
  $("worstScoreValue").textContent = signed(combined);
  $("worstScoreValue").className = `dw-bar-value mono ${positive ? "positive" : "negative"}`;
  $("worstScoreBarFill").className = `dw-bar-fill ${positive ? "positive" : "negative"}`;
  $("worstScoreBarFill").style.width = `${Math.min(SCORE_MAX, Math.abs(combined))}%`;
  setRisk($("warningTitle"), riskOf(combined));
  setRisk($("hostLabel"), riskOf(combined));
  if (vt !== null) { $("vtScoreRow").hidden = false; $("vtScoreValue").textContent = signed(vt); setRisk($("vtScoreValue"), riskOf(vt)); }
  if (host !== null) { $("hostScoreRow").hidden = false; $("hostConfidenceValue").textContent = signed(host); setRisk($("hostConfidenceValue"), riskOf(host)); }
}

// ── VirusTotal box ───────────────────────────────────────────────────────────
function engineCounts(stats, suffix) {
  const frag = document.createDocumentFragment();
  const cells = [
    ["Not harmful:", (stats.harmless || 0) + (stats.undetected || 0), "dw-ec-harmless"],
    ["Unknown:", stats.unknown || 0, "dw-ec-unknown"],
    ["Suspicious:", stats.suspicious || 0, "dw-ec-suspicious"],
    ["Malicious:", stats.malicious || 0, "dw-ec-malicious"]
  ];
  for (const [label, value, cls] of cells) {
    const l = document.createElement("span"); l.className = "dw-ec-label"; l.textContent = label;
    const n = document.createElement("span"); n.className = `dw-ec-num ${cls}`; n.textContent = String(value);
    frag.append(l, n);
  }
  frag.append(suffix);
  return frag;
}

function renderVt(r) {
  const list = $("vtDetailsList");
  list.replaceChildren();
  $("vtClassificationLine").hidden = true;
  $("vtUnknownLine").hidden = true;
  $("vtBox").hidden = false;
  $("vtNoKey").hidden = !!r.vtApiKeySet;
  if (!r.vtApiKeySet) return;                                     // the box says "skipped" + the key link
  if (!vtKnown(r)) { if (r.vtDone) $("vtUnknownLine").hidden = false; return; }

  const raw = r.vtRawStats || {};
  if (raw.malicious !== undefined) {
    const all = document.createElement("span"); all.className = "dw-ec-suffix"; all.textContent = "(all results)";
    const row1 = document.createElement("li"); row1.append(engineCounts(raw, all)); list.append(row1);
    if ((r.vtFpLevel || FP_LEVEL.NONE) !== FP_LEVEL.NONE && r.vtFilteredStats) {
      const link = document.createElement("a"); link.href = "#"; link.textContent = "(with FP reduction)";
      link.addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
      const row2 = document.createElement("li"); row2.append(engineCounts(r.vtFilteredStats, link)); list.append(row2);
    }
  }
  const age = r.vtBreakdown && r.vtBreakdown.age && r.vtBreakdown.age.ageDays;
  if (typeof age === "number") {
    const days = Math.round(age);
    list.append(li(`First submitted to VT: ${days} day${days === 1 ? "" : "s"} ago`));
  }
  // The classification line only when the summary box above does not already say it in VT words.
  const summaryNotInVtWords = !hostOf(r) || (hostScoreOf(r) ?? 0) < 0;   // DS: topBoxIsVtText inverted
  if (r.vtBreakdown && r.vtBreakdown.detection && summaryNotInVtWords) {
    const risk = riskOf(r.vtScore);
    $("vtClassificationLine").textContent = VT_RATING_TEXT[risk] || "";
    setRisk($("vtClassificationLine"), risk);
    $("vtClassificationLine").hidden = false;
  }
}

// ── Host reputation + heuristics boxes ───────────────────────────────────────
function renderHost(r) {
  const h = hostOf(r);
  if (!h) return;
  const vt = vtKnown(r) ? r.vtScore : null;
  if (h.score === null && vt !== null) { $("hostBox").hidden = true; }
  else {
    $("hostBox").hidden = false;
    if (vt !== null) {
      const risk = riskOf(clampScore(vt + (hostScoreOf(r) ?? 0)));
      $("hostResult").textContent = VT_RATING_TEXT[risk] || "";
      setRisk($("hostResult"), risk);
    } else {
      $("hostResult").textContent = sanitizeLabel(h.label || h.classification || "See heuristics below");
      setRisk($("hostResult"), riskOfClassification(h.classification));
    }
  }

  const list = $("hostDetailsList");
  list.replaceChildren();
  // DNS threat-intel lines — always shown; a slot set to "None" (SKIPPED) shows nothing.
  for (const c of h.dnsChecks || []) {
    if (!c || !c.status || c.status === DNS_STATUS.SKIPPED) continue;
    const who = c.providerLabel || "DNS check";
    if (c.status === DNS_STATUS.BLOCKED) list.append(li(`Domain is on the ${who} blacklist (confirmed malicious)`));
    else if (c.status === DNS_STATUS.ALLOWED) list.append(li(`Not flagged as malware at ${who}`));
    else list.append(li(`${who}: ${DNS_UNKNOWN_TEXT[c.reasonCode] || DNS_UNKNOWN_FALLBACK}`));
  }
  const rows = h.breakdown || [];
  for (const row of rows) {
    if (row.source === DNS_SOURCE) continue;
    if (row.explained) list.append(li(sanitizeLabel(row.label), ROW_CLASS.EXPLAINED));
    else if (row.score > 0) list.append(li(sanitizeLabel(row.label), ROW_CLASS.CREDIT));
    else if (row.score < 0) list.append(li(sanitizeLabel(row.label)));
  }
  // Domain age, unless the RDAP row above already said it.
  if (h.rdap && h.rdap.label && !rows.some((row) => row.source === RDAP_SOURCE && row.score < 0)) {
    list.append(li(`Domain registration age: ${sanitizeLabel(h.rdap.label)}`));
  }
  if (!list.children.length) list.append(li(NO_HEURISTIC_SIGNALS, "dw-empty"));
  $("heuristicsBox").hidden = false;
}

let lastModel = null;
const ownDownloadId = Number.parseInt(new URLSearchParams(location.search).get(DOWNLOAD_ID_PARAM), DECIMAL_RADIX);

// A late VirusTotal verdict for THIS page's download, from this extension's service worker only.
function onLiveUpdate(msg, sender) {
  if (!sender || sender.id !== chrome.runtime.id || !msg || msg.type !== M.MSG_DOWNLOAD_VT_UPDATE) return;
  if (msg.downloadId !== ownDownloadId || !lastModel || !msg.record) return;
  render({ ...lastModel, record: msg.record });
}

function render(model) {
  lastModel = model;
  const r = model.record;
  lastRecord = r;
  applyLook(model.look);
  $("srcUrl").textContent = (r.url || "Unknown URL").replace(URL_CUT_RE, "");
  $("reasonText").textContent = r.confirmedExt || r.ext ? `.${r.confirmedExt || r.ext}` : "Unknown";
  renderDisclaimer(r);
  renderVt(r);
  renderHost(r);
  renderScores(r);
}

// ── Actions ──────────────────────────────────────────────────────────────────
function vtTargetUrl() {
  if (!lastRecord) return VT_GUI_HOME_URL;
  if (lastRecord.vtApiKeySet && !vtKnown(lastRecord)) return HYBRID_ANALYSIS_URL;
  return lastRecord.url ? `${VT_GUI_URL_PREFIX}${UrlUtils.toVtUrlId(lastRecord.url)}${VT_GUI_URL_SUFFIX}` : VT_GUI_HOME_URL;
}

function setButtons(disabled) { for (const id of BUTTON_IDS) $(id).disabled = disabled; }

async function finish(openUrl) {
  if (busy) return;
  busy = true;
  setButtons(true);
  try {
    const res = await chrome.runtime.sendMessage({ type: M.MSG_DISMISS_DOWNLOAD });
    if (!res || !res.ok) throw new Error(res && res.error || "no response");
    if (openUrl) await chrome.tabs.create({ url: openUrl });
    window.close();
  } catch (e) {
    showError($("dwStatus"), e, "That did not work");
    busy = false;                                          // release so the user can try again
    setButtons(false);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("btnOk").addEventListener("click", () => finish(null));
  $("btnVt").addEventListener("click", () => finish(vtTargetUrl()));
  $("vtKeyLink").addEventListener("click", (e) => { e.preventDefault(); chrome.tabs.create({ url: VT_JOIN_URL }); });
  chrome.runtime.onMessage.addListener(onLiveUpdate);
  $("btnVt").focus();                                        // 4.4.6: the careful choice is the default
  $("warningTitle").textContent = DOWNLOAD_WARNING_TITLE_DEFAULT;   // until the chosen title arrives
  try {
    const res = await chrome.runtime.sendMessage({ type: M.MSG_GET_DOWNLOAD_CHECK });
    if (!res || !res.ok) throw new Error(res && res.error || "no response");
    if (!res.data) { $("srcUrl").textContent = GONE_TEXT; $("reasonText").textContent = "—"; return; }
    render(res.data);
  } catch (e) {
    showError($("dwStatus"), e, "Could not load the download check");
    console.warn(LOG_PREFIX, "download warning:", e);
  }
});

window.addEventListener("pagehide", () => {                 // release timers and the live-update listener
  releaseStatus();
  chrome.runtime.onMessage.removeListener(onLiveUpdate);
});
