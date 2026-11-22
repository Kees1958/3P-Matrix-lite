// ── core/matrix-overrides.js ──────────────────────────────────────────────────
// Show Matrix overrides — pure operations on state.matrixRules. Overrides are always global
// (stored under MATRIX_SITE_ALL, uMatrix / 3P-Matrix-lite model). No Chrome API calls.
// (4.2.3: moved out of background.js — audit finding 6; behaviour unchanged.)
//
// Public interface:
//   globalMatrixOverrides(state)                   — { [domain]: { script?, frame? } } (never null)
//   setMatrixOverride(state, domain, scope, action) — set one scope (action BLOCK/ALLOW) or clear it
//                                                    (action null); empty entries and an empty
//                                                    list are removed. Throws when a NEW domain
//                                                    would exceed MATRIX_OVERRIDES_CAP.
// Input validation (host, scope, action) is the caller's boundary job (background.js router).
// ─────────────────────────────────────────────────────────────────────────────

import { MATRIX_SITE_ALL, MATRIX_OVERRIDES_CAP } from "../data/constants.js";

export function globalMatrixOverrides(state) {
  return state.matrixRules[MATRIX_SITE_ALL] || {};
}

export function setMatrixOverride(state, domain, scope, action) {
  const overrides = { ...globalMatrixOverrides(state) };
  const entry = { ...(overrides[domain] || {}) };
  const isNewDomain = !overrides[domain];
  if (action === null) delete entry[scope]; else entry[scope] = action;
  if (isNewDomain && action !== null && Object.keys(overrides).length >= MATRIX_OVERRIDES_CAP) throw new Error("matrix override limit reached");
  if (Object.keys(entry).length) overrides[domain] = entry; else delete overrides[domain];
  if (Object.keys(overrides).length) state.matrixRules[MATRIX_SITE_ALL] = overrides; else delete state.matrixRules[MATRIX_SITE_ALL];
}
