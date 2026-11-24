// ── ui/derived-text.js — values shown in UI text, derived from their source ──────
// Any number or list a page SHOWS that also exists as a constant or registry field (a level, a
// protection number, a score threshold, a level range) is rendered from that source here — never
// typed into HTML or a JS string (B2a, C39a). Changing the constant then updates every page.
//
// Public interface:
//   fillDerivedText(root)    — fills every <… data-derived="KEY"> under root from DERIVED_TEXT
//   protectionNum(key)       — display number of a protection (data/protections.js `num`)
//   protectionLabel(key)     — popup label of a protection (data/protections.js `label`)
//   formatScore(n)           — score with a typographic minus ("−30")
//   levelRange()             — [LEVEL_MIN … LEVEL_MAX] as an array (ticks, selects)
//
// HTML usage:   <span data-derived="score-suspect-at"></span>   (empty in the markup on purpose)
// Guard: an unknown key is logged and its element is marked data-derived-missing, so a typo
// shows up in the console and in the check suite (tools/check-derived-literals.mjs) instead of
// silently rendering an empty span.
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, LEVEL_MIN, LEVEL_MAX, DOWNLOAD_BLOCK_EXEMPT_LEVELS, DOWNLOAD_PAGE_TRUST_LEVELS, SITE_DIALOG_FROM, SAFER_REGIONS_LEVELS, SCORE, LOG_PREFIX, AUTO_ALLOW_THRESHOLD_MIN,
         AUTO_ALLOW_THRESHOLD_MAX, DOWNLOAD_DEFAULTS, BUILTIN_TRUSTED_DOWNLOAD_DOMAINS,
         DOWNLOAD_WARNING_TITLE_DEFAULT, TAMPER_COUNTDOWN_S, TAMPER_LEVEL, TAMPER_RATING, TAMPER_RATING_MIN_POINTS,
         TAMPER_SENSITIVE_FACTOR, TAMPER_SUSPICIOUS_WARN, BADGE_TEXT } from "../data/constants.js";
import { PROTECTION_BY_KEY, PROTECTION_KEY } from "../data/protections.js";

const DERIVED_ATTR   = "data-derived";
const MISSING_ATTR   = "data-derived-missing";
const MINUS_SIGN     = "−";                  // typographic minus, as in the existing UI text
export const LIST_SEPARATOR = ", ";   // also ui/popup.js (4.5.6 whitelist summary)
const RGB_CHANNELS   = Object.freeze(["r", "g", "b"]);

export function protectionNum(key) {
  const p = PROTECTION_BY_KEY[key];
  if (!p) { console.error(LOG_PREFIX, "derived-text: unknown protection key", key); return "?"; }
  return String(p.num);
}

export function protectionLabel(key) {
  const p = PROTECTION_BY_KEY[key];
  if (!p) { console.error(LOG_PREFIX, "derived-text: unknown protection key", key); return "?"; }
  return p.label;
}

export function formatScore(n) {
  return n < 0 ? MINUS_SIGN + String(-n) : String(n);
}

export function levelRange() {
  const out = [];
  for (let n = LEVEL_MIN; n <= LEVEL_MAX; n++) out.push(n);
  return out;
}

// THE table of derived values pages may show. Key = data-derived attribute value.
const DERIVED_TEXT = Object.freeze({
  "level-allow-all":        () => String(LEVEL.ALLOW_ALL),
  "safer-regions-levels":   () => SAFER_REGIONS_LEVELS.join(LIST_SEPARATOR),
  "score-suspect-at":       () => formatScore(SCORE.SUSPECT_AT),
  // 4.4.1: "−45 at level 2, −30 at level 3, …" — the site dialog line per protection level (SITE_DIALOG_FROM)
  "site-dialog-levels":     () => Object.entries(SITE_DIALOG_FROM)
                                    .map(([lvl, from]) => `${formatScore(from)} at level ${lvl}`).join(LIST_SEPARATOR),
  "protection-num-warn":    () => protectionNum(PROTECTION_KEY.WARN_SUSPICIOUS_SITES),
  "protection-label-warn":  () => protectionLabel(PROTECTION_KEY.WARN_SUSPICIOUS_SITES),
  "protection-label-download": () => protectionLabel(PROTECTION_KEY.WARN_RISKY_DOWNLOADS),
  "protection-label-block-download": () => protectionLabel(PROTECTION_KEY.BLOCK_RISKY_DOWNLOADS),
  "auto-allow-min":         () => String(AUTO_ALLOW_THRESHOLD_MIN),
  "auto-allow-max":         () => String(AUTO_ALLOW_THRESHOLD_MAX),
  "auto-allow-default":     () => String(DOWNLOAD_DEFAULTS.autoAllowThreshold),
  "trusted-download-builtin": () => BUILTIN_TRUSTED_DOWNLOAD_DOMAINS.join(LIST_SEPARATOR),
  // 4.5.5: where blockRiskyDownloads honours the trusted download domains, and where it blocks regardless
  "block-exempt-levels":    () => DOWNLOAD_BLOCK_EXEMPT_LEVELS.join(LIST_SEPARATOR),
  "page-trust-levels":      () => DOWNLOAD_PAGE_TRUST_LEVELS.join(LIST_SEPARATOR),
  "block-strict-levels":    () => levelRange().filter((l) => l >= PROTECTION_BY_KEY[PROTECTION_KEY.BLOCK_RISKY_DOWNLOADS].fromLevel &&
                                                         !DOWNLOAD_BLOCK_EXEMPT_LEVELS.includes(l)).join(LIST_SEPARATOR),
  "warning-color-default":  () => RGB_CHANNELS.map((ch) => DOWNLOAD_DEFAULTS.warningColor[ch]).join(LIST_SEPARATOR),
  "download-title-default": () => DOWNLOAD_WARNING_TITLE_DEFAULT,
  // 5.1.0 — Tamper Guard: from which level each option applies (its registry fromLevel), and the countdown
  "tamper-level-sensitive": () => levelsFrom(PROTECTION_BY_KEY[PROTECTION_KEY.WATCH_TAMPER_SENSITIVE].fromLevel),
  // 5.1.3 — Scam protection: from which level the switch (and its frames part) applies (registry fromLevel)
  "scam-level-from":        () => String(PROTECTION_BY_KEY[PROTECTION_KEY.ENABLE_SCAM_PROTECTION].fromLevel),
  "scam-frames-level-from": () => String(PROTECTION_BY_KEY[PROTECTION_KEY.BLOCK_REDIRECTS_DIALOGS].fromLevel),
  "tamper-level-after-sign": () => levelsFrom(TAMPER_LEVEL.AFTER_SIGN),
  "tamper-level-always":    () => levelsFrom(TAMPER_LEVEL.ALWAYS),
  // single "from" levels for the "How Tamper Guard works" lines
  "tamper-level-after-sign-from": () => String(TAMPER_LEVEL.AFTER_SIGN),
  "tamper-countdown-s":     () => String(TAMPER_COUNTDOWN_S),
  "protection-label-tamper": () => protectionLabel(PROTECTION_KEY.WATCH_TAMPER_SENSITIVE),
  // 5.1.3 — the risk rating (data/constants.js TAMPER_RATING_*, TAMPER_SUSPICIOUS_WARN) and the quiet toolbar mark
  "tamper-points-suspicious": () => String(TAMPER_RATING_MIN_POINTS[TAMPER_RATING.SUSPICIOUS]),
  "tamper-points-high":       () => String(TAMPER_RATING_MIN_POINTS[TAMPER_RATING.HIGH]),
  "tamper-points-critical":   () => String(TAMPER_RATING_MIN_POINTS[TAMPER_RATING.CRITICAL]),
  "tamper-sensitive-factor":  () => String(TAMPER_SENSITIVE_FACTOR),
  "tamper-suspicious-always": () => levelsFrom(TAMPER_SUSPICIOUS_WARN.ALWAYS_FROM),
  "tamper-suspicious-outside": () => String(TAMPER_SUSPICIOUS_WARN.OUTSIDE_SAFER_FROM),
  "tamper-mark":              () => BADGE_TEXT.SUSPECT
});

// 5.1.0: "2–5" — the levels from `from` up to LEVEL_MAX.
const RANGE_DASH = "–";
function levelsFrom(from) {
  return from === LEVEL_MAX ? String(from) : `${from}${RANGE_DASH}${LEVEL_MAX}`;
}

export function fillDerivedText(root) {
  if (!root || typeof root.querySelectorAll !== "function") return;
  for (const el of root.querySelectorAll(`[${DERIVED_ATTR}]`)) {
    const key = el.getAttribute(DERIVED_ATTR);
    const derive = DERIVED_TEXT[key];
    if (!derive) {
      el.setAttribute(MISSING_ATTR, "");
      console.error(LOG_PREFIX, "derived-text: unknown key", key);
      continue;
    }
    el.textContent = derive();
  }
}
