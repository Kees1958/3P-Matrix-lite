// ── ui/tamper-warning.js — Tamper Guard warning window controller (5.1.0) ───────────────
// Shows the page's risk rating and every Tamper Guard finding on it (5.1.3, core/tamper-warnings.js warningModel): what
// changed, on which site, the names or hosts it is about (never values). The service worker tells this window when more
// was found (MSG_TAMPER_WARNING_CHANGED): it fetches the model again; a rating that became critical stops the countdown. Ignore closes it; "Always ignore on this site" (5.1.3) adds "Tamper: site" to the allow list
// (the second asks for confirmation first) and close it. A non-critical warning closes itself after the countdown;
// ANY interaction (pointer, key, focus on a button) stops the countdown so the user can read and choose. A critical
// one never counts down. The warning id is read by the service worker from this page's URL (C28) — the page never
// sends it. Texts go in via textContent (C48); failures show in the status line.
// State: busy (one action at a time), countdown timer — released on every outcome and with the page (B10).
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { LOG_PREFIX, TAMPER_COUNTDOWN_TICK_MS, TAMPER_RATING, TAMPER_WARNING_ID_PARAM } from "../data/constants.js";
import { TAMPER_DETAIL } from "../data/tamper-rules.js";
import { fillDerivedText } from "./derived-text.js";
import { showError, releaseStatus } from "./status-line.js";

// ── Settings (one place) ─────────────────────────────────────────────────────
const BUTTON_IDS = Object.freeze(["btnIgnore", "btnAlwaysIgnore"]);   // 5.1.3: "Never warn anywhere" removed
const GONE_TEXT = "This warning is no longer available — you can close this window.";
const DETAIL_HEAD = Object.freeze({
  [TAMPER_DETAIL.TARGETS]: "What was replaced:",
  [TAMPER_DETAIL.KEYS]:    "Fields that were changed (names only):",
  [TAMPER_DETAIL.DEST]:    "Where to:"
});
const RATING_CLASS = Object.freeze({ [TAMPER_RATING.CRITICAL]: "tg-critical", [TAMPER_RATING.HIGH]: "tg-high",
                                     [TAMPER_RATING.SUSPICIOUS]: "tg-suspicious" });
const TITLE = "This page shows signs of tampering";
const SENSITIVE_TEXT = "Counted heavier: this looks like a banking or payment page.";
// This window's own id (?w=) — only to recognise a "changed" message meant for it; the service worker never takes
// the id from what this page sends (C28).
const OWN_ID = new URL(location.href).searchParams.get(TAMPER_WARNING_ID_PARAM);
function summaryText(m) {
  const n = m.signals.length;
  return `${n === 1 ? "One sign" : `${n} signs`} of tampering found — risk: ${m.ratingLabel} (${m.score} points). ` +
    "Hover a line for what it means.";
}
const STOP_EVENTS = Object.freeze(["pointerdown", "keydown", "wheel"]);

let busy = false;
let countdownTimer = null;
let secondsLeft = 0;

function $(id) { return document.getElementById(id); }
function countdownText(s) { return `This warning closes itself in ${s} s — click or press a key to keep it open.`; }
function setButtons(disabled) { for (const id of BUTTON_IDS) $(id).disabled = disabled; }

// ── Countdown (guarded: one timer; stopped on interaction, on every action, with the page) ──
function stopCountdown() {
  if (countdownTimer !== null) { clearInterval(countdownTimer); countdownTimer = null; }
  $("tgCountdown").hidden = true;
}
function startCountdown(seconds) {
  if (!seconds) return;
  secondsLeft = seconds;
  $("tgCountdown").hidden = false;
  $("tgCountdown").textContent = countdownText(secondsLeft);
  countdownTimer = setInterval(() => {
    secondsLeft -= 1;
    if (secondsLeft <= 0) { stopCountdown(); act(M.TAMPER_WARNING_ACTION.IGNORE); return; }
    $("tgCountdown").textContent = countdownText(secondsLeft);
  }, TAMPER_COUNTDOWN_TICK_MS);
  for (const type of STOP_EVENTS) window.addEventListener(type, stopCountdown, { capture: true, once: true });
}

function signalItem(s) {
  const li = document.createElement("li");
  li.title = `${s.description} (${s.points} points)`;
  const name = document.createElement("span"); name.className = "tg-signal-name"; name.textContent = s.label;
  li.append(name);
  if (s.items.length) {
    const items = document.createElement("span"); items.className = "tg-signal-items";
    items.textContent = `${s.detailHead || DETAIL_HEAD[s.detailKind] || ""} ${s.items.join(", ")}`.trim();   // 5.1.2: a rule's own heading first
    li.append(items);
  }
  return li;
}

let rendered = false;
function render(m) {
  document.title = `3P Matrix — ${TITLE}`;
  $("tgTitle").textContent = TITLE;
  $("tgRating").textContent = m.ratingLabel;
  $("tgRating").className = `tg-severity ${RATING_CLASS[m.rating] || ""}`.trim();
  $("tgSite").textContent = m.site;
  $("tgSummary").textContent = summaryText(m);
  $("tgSignals").replaceChildren(...m.signals.map(signalItem));
  $("tgContext").textContent = m.sensitive ? SENSITIVE_TEXT : "";
  if (m.critical) stopCountdown();                             // became critical: wait for a choice
  else if (!rendered) startCountdown(m.countdownS);            // an update never restarts the countdown
  rendered = true;
}

async function load() {
  const res = await chrome.runtime.sendMessage({ type: M.MSG_GET_TAMPER_WARNING });
  if (!res || !res.ok) throw new Error(res && res.error || "no response");
  if (!res.data) { $("tgTitle").textContent = GONE_TEXT; setButtons(true); stopCountdown(); return false; }
  render(res.data);
  return true;
}

// 5.1.3: more was found on the page — fetch the model again (only messages from this extension, for this window).
function onChanged(msg, sender) {
  if (!sender || sender.id !== chrome.runtime.id || !msg || msg.type !== M.MSG_TAMPER_WARNING_CHANGED || msg.id !== OWN_ID) return false;
  if (!busy) load().catch((e) => showError($("tgStatus"), e, "Could not update the warning"));
  return false;
}

async function act(action) {
  if (busy) return;
  busy = true;
  stopCountdown();
  setButtons(true);
  try {
    const res = await chrome.runtime.sendMessage({ type: M.MSG_TAMPER_WARNING_ACTION, action });
    if (!res || !res.ok) throw new Error(res && res.error || "no response");
    window.close();                                            // the service worker closes it too; either is fine
  } catch (e) {
    showError($("tgStatus"), e, "That did not work");
    busy = false;                                              // release so the user can try again
    setButtons(false);
  }
}

function onButton(action) {
  return (e) => { if (e.isTrusted) act(action); };            // real clicks only
}

document.addEventListener("DOMContentLoaded", async () => {
  fillDerivedText(document);
  $("btnIgnore").addEventListener("click", onButton(M.TAMPER_WARNING_ACTION.IGNORE));
  $("btnAlwaysIgnore").addEventListener("click", onButton(M.TAMPER_WARNING_ACTION.ALWAYS_IGNORE));
  chrome.runtime.onMessage.addListener(onChanged);
  try {
    if (await load()) $("btnIgnore").focus({ preventScroll: true });
  } catch (e) {
    showError($("tgStatus"), e, "Could not load the warning");
    console.warn(LOG_PREFIX, "Tamper Guard warning:", e);
  }
});

window.addEventListener("pagehide", () => {
  stopCountdown();
  releaseStatus();
  chrome.runtime.onMessage.removeListener(onChanged);         // release (B10)
});
