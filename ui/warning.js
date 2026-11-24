// ── ui/warning.js — warning dialog controller ─────────────────────────────────
// Shows the suspicious site (from ?u=), asks the service worker for the full
// stage 1 + stage 2 evaluation, and sends the user's choice back.
// 4.6.0: ?x=<channel id> (data/exfil-channels.js) — the page tried to send data to a phishing channel and 3P Matrix
// blocked it: red look, the reason as the first signal, and "Go back" leaves the site (the service worker decides
// that from this page's own URL, C28).
// 4.7.0: ?x=<page-scam reason id> (data/page-scam-reasons.js) — ClickFix, ConsentFix (red, same shape as an
// exfiltration channel) or deviceCode (amber "attention" look, no risk score, no Trust button, custom button
// labels and small print — see PAGE_SCAM_REASON_BY_ID). ?r=<referrer> (device-code only) — the site that sent the
// user, for the {referrer} placeholder; display only, read nowhere else.
// All site text goes into the DOM via textContent.
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { SEVERITY, ICON_DIR, LOG_PREFIX, WARNING_TARGET_PARAM, WARNING_REASON_PARAM, WARNING_REFERRER_PARAM, LEVEL, LEVEL_INFO, ICON_UI_SIZE } from "../data/constants.js";
import { EXFIL_CHANNEL_BY_ID } from "../data/exfil-channels.js";
import { PAGE_SCAM_REASON_BY_ID, RUN_PLACE_BY_OS, UNKNOWN_REFERRER_TEXT, LOOK, ALLOW_FROM, ALWAYS_LABEL } from "../data/page-scam-reasons.js";
import { fillDerivedText } from "./derived-text.js";
import { showError, releaseStatus } from "./status-line.js";

// ── Severity presentation (single table) ─────────────────────────────────────
// Look per severity = the level look it mirrors (data/constants.js LEVEL_INFO: orange brick wall
// for "suspicious", red for "phishing") — no colour or icon name typed here (finding 14).
const SUSPECT_LOOK  = LEVEL_INFO[LEVEL.HIGH - 1];
const PHISHING_LOOK = LEVEL_INFO[LEVEL.STRICT - 1];
const PHISHING_COLOR = "var(--block)";        // ui/common.css token (readable red on the dark dialog)
const SEVERITY_VIEW = Object.freeze({
  [SEVERITY.SUSPECT]: {
    color: SUSPECT_LOOK.color, icon: SUSPECT_LOOK.icon,
    title: "This site needs your attention",
    intro: "The address shows signs that are common on malware and phishing sites. Don’t provide sensitive information or install something without double checking."
  },
  [SEVERITY.PHISHING]: {
    color: PHISHING_COLOR, icon: PHISHING_LOOK.icon,
    title: "This site may be trying to trick you",
    intro: "The address shows strong signs that it is a scam, trying to trick you into providing sensitive information or installing something. It looks like malware or phishing!"
  }
});
// 4.7.0 — the "attention" look for a page-scam reason that is not itself phishing (deviceCode: the page is real).
const ATTENTION_COLOR = SUSPECT_LOOK.color;

function $(id) { return document.getElementById(id); }
const params = new URLSearchParams(location.search);
const target = params.get(WARNING_TARGET_PARAM) || "";
const reasonParam = params.get(WARNING_REASON_PARAM);
const exfilChannel = EXFIL_CHANNEL_BY_ID[reasonParam] || null;             // unknown id → ordinary warning
const pageScam = PAGE_SCAM_REASON_BY_ID[reasonParam] || null;              // mutually exclusive with exfilChannel
let busy = false;                                         // guard: one action at a time

// {place} (ClickFix) / {referrer} (deviceCode) filled from this browser's platform / the warning URL's own ?r=.
function runPlace() {
  const platform = (navigator.userAgentData && navigator.userAgentData.platform || navigator.platform || "").toLowerCase();
  if (platform.includes("win")) return RUN_PLACE_BY_OS.win;
  if (platform.includes("mac")) return RUN_PLACE_BY_OS.mac;
  if (platform.includes("linux") || platform.includes("cros")) return platform.includes("cros") ? RUN_PLACE_BY_OS.cros : RUN_PLACE_BY_OS.linux;
  return RUN_PLACE_BY_OS.default;
}
function fillPlaceholders(text) {
  return text.replace("{place}", runPlace()).replace("{referrer}", params.get(WARNING_REFERRER_PARAM) || UNKNOWN_REFERRER_TEXT);
}

// 4.6.0: the exfiltration view — text per channel built from the channel's own label (no typed copy per channel).
function exfilView(channel) {
  return {
    title: "This page tried to send your data away",
    intro: `Phishing pages send passwords and card details they collect to ${channel.label}. 3P Matrix blocked it. Don’t enter anything on this page.`,
    signal: `This page tried to send data to ${channel.label} — typical of a phishing page`
  };
}

// 4.7.0 — a page-scam reason's own view, straight from its table entry.
function pageScamView(scam) {
  return {
    title: fillPlaceholders(scam.title),
    intro: fillPlaceholders(scam.intro),
    signal: fillPlaceholders(scam.signal)
  };
}

function setButtons(disabled) {
  ["btnBack", "btnTrust", "btnContinue"].forEach((id) => { if (!$(id).hidden) $(id).disabled = disabled; });
}

function showSeverity(sev) {
  const forcedSeverity = exfilChannel || (pageScam && pageScam.look !== LOOK.ATTENTION) ? SEVERITY.PHISHING : sev;
  const base = SEVERITY_VIEW[forcedSeverity] || SEVERITY_VIEW[SEVERITY.SUSPECT];
  const extra = exfilChannel ? exfilView(exfilChannel) : (pageScam ? pageScamView(pageScam) : null);
  const color = pageScam && pageScam.look === LOOK.ATTENTION ? ATTENTION_COLOR : base.color;
  const v = extra ? { ...base, ...extra, color } : base;
  document.documentElement.style.setProperty("--sev", v.color);
  $("warnIcon").src = `../${ICON_DIR}/${v.icon}_${ICON_UI_SIZE}.png`;
  $("warnTitle").textContent = v.title;
  $("warnIntro").textContent = v.intro;
  document.title = `3P Matrix — ${v.title}`;
}

function showSignals(list) {
  const reasonSignal = exfilChannel ? exfilView(exfilChannel).signal : (pageScam ? pageScamView(pageScam).signal : null);
  const all = reasonSignal ? [reasonSignal, ...list] : list;
  $("warnSignals").replaceChildren(...all.map((s) => { const li = document.createElement("li"); li.textContent = s; return li; }));
}

// 4.7.0 — a page-scam reason may replace the button labels, hide Trust (canTrust: false) and replace the small
// print (note); everything else (exfiltration, ordinary site warnings) keeps the page's defaults.
// 5.1.3: the Trust button is "Always allow" (a block) / "Always ignore" (a warning) — it adds one allow-list line of
// the warning's category (decided by the service worker). Hidden when the line would name the sender and there is none.
function applyAlwaysButton() {
  const label = pageScam ? (pageScam.allow && pageScam.allow.label) : (exfilChannel ? ALWAYS_LABEL.ALLOW : ALWAYS_LABEL.IGNORE);
  if (label) $("btnTrust").textContent = label;
  if (pageScam && pageScam.allow && pageScam.allow.from === ALLOW_FROM.SENDER && !params.get(WARNING_REFERRER_PARAM)) $("btnTrust").hidden = true;
}

function applyPageScamLayout() {
  applyAlwaysButton();
  if (!pageScam) return;
  if (pageScam.back) $("btnBack").textContent = pageScam.back;
  if (pageScam.cont) $("btnContinue").textContent = pageScam.cont;
  if (pageScam.canTrust === false) $("btnTrust").hidden = true;
  if (pageScam.note) $("warnNote").textContent = pageScam.note;
  if (!pageScam.scoreSite) { $("warnScore").hidden = true; $("warnChecking").hidden = true; }
}

async function action(kind) {
  if (busy) return;
  busy = true;
  setButtons(true);
  try {
    const res = await chrome.runtime.sendMessage({ type: M.MSG_WARNING_ACTION, action: kind, url: target });
    if (!res || !res.ok) throw new Error(res && res.error);
  } catch (e) {
    showError($("warnStatus"), e, "That did not work");
    busy = false;                                         // release so the user can try again
    setButtons(false);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  fillDerivedText(document);
  let host = "";
  try { host = new URL(target).host; } catch { /* malformed — leave empty */ }
  $("warnHost").textContent = host || target;
  showSeverity(SEVERITY.SUSPECT);
  showSignals([]);                                       // the reason (exfiltration / page scam) shows before the score arrives
  applyPageScamLayout();

  $("btnBack").addEventListener("click", () => action(M.WARNING_ACTION.GO_BACK));
  $("btnTrust").addEventListener("click", () => action(M.WARNING_ACTION.TRUST));
  $("btnContinue").addEventListener("click", () => action(M.WARNING_ACTION.CONTINUE_ONCE));
  $("optionsLink").addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
  $("btnBack").focus();

  if (pageScam && !pageScam.scoreSite) return;            // 4.7.0: deviceCode — the page is real, no score to fetch

  try {
    const res = await chrome.runtime.sendMessage({ type: M.MSG_EVALUATE_SITE, url: target });
    if (!res || !res.ok || !res.data) throw new Error(res && res.error || "not scorable");
    const r = res.data;
    showSeverity(r.severity === SEVERITY.NONE ? SEVERITY.SUSPECT : r.severity);
    $("warnScore").textContent = `risk score ${r.score}`;
    showSignals(r.signals);
  } catch (e) {
    $("warnScore").textContent = "score unavailable";
    console.warn(LOG_PREFIX, "warning: evaluate", e);     // visible: "score unavailable" above
  } finally {
    $("warnChecking").hidden = true;
  }
});

window.addEventListener("pagehide", releaseStatus);          // release status timers with the page
