// ── ui/status-line.js — one short, self-clearing message line per page area ───────
// Every page shows the outcome of a user action the same way: a status line that says what
// happened ("Saved.", "Not saved: …") and clears itself after STATUS_CLEAR_MS. Failures are never
// left in the console only (C5/C13, audit finding 10).
//
// Public interface:
//   showStatus(el, text, kind?)   — kind: STATUS_KIND.OK (default) | STATUS_KIND.ERROR
//   showError(el, err, prefix?)   — "prefix: message" as an error (prefix defaults to "Not saved")
//   releaseStatus()               — clear every pending timer (pagehide)
//
// Guards: one timer per element (a new message replaces the old one and its timer); every timer
// is released when it fires, when replaced, or on releaseStatus(); a missing element is ignored.
// ─────────────────────────────────────────────────────────────────────────────

import { STATUS_CLEAR_MS } from "../data/constants.js";

export const STATUS_KIND = Object.freeze({ OK: "ok", ERROR: "error" });
const ERROR_CLASS = "status-error";
const COLLAPSING_CLASS = "status-line";      // these lines hide when empty; others (options .status) keep their space
const DEFAULT_ERROR_PREFIX = "Not saved";
const _timers = new Map();                     // element → timer id

function clearTimer(el) {
  const t = _timers.get(el);
  if (t !== undefined) { clearTimeout(t); _timers.delete(el); }
}

export function showStatus(el, text, kind = STATUS_KIND.OK) {
  if (!el) return;
  clearTimer(el);
  el.textContent = text;
  el.classList.toggle(ERROR_CLASS, kind === STATUS_KIND.ERROR);
  if (el.classList.contains(COLLAPSING_CLASS)) el.hidden = !text;
  _timers.set(el, setTimeout(() => {
    _timers.delete(el);
    el.textContent = "";
    el.classList.remove(ERROR_CLASS);
    if (el.classList.contains(COLLAPSING_CLASS)) el.hidden = true;
  }, STATUS_CLEAR_MS));
}

export function showError(el, err, prefix = DEFAULT_ERROR_PREFIX) {
  const msg = (err && err.message) || String(err || "unknown error");
  showStatus(el, `${prefix}: ${msg}`, STATUS_KIND.ERROR);
}

export function releaseStatus() {
  for (const t of _timers.values()) clearTimeout(t);
  _timers.clear();
}
