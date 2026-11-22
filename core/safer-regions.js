// ── core/safer-regions.js ─────────────────────────────────────────────────────────
// Safer regions (TLD whitelist) recomputation — thin async wrapper around
// 3P-Matrix-lite's tld-engine (BASE_TLDS + auto-added country codes + manual
// − excluded). The engine itself stays pure; this module supplies the two
// environment inputs (browser languages, time zone).
//
// Public interface:
//   computeSaferRegions(safeZone) — Promise<string[]> merged TLD list (capped)
//   editSaferRegions(safeZone, edit) — Promise<void> apply one popup edit + recompute (in place)
//
// The auto-add scope is fixed (SAFER_REGIONS_AUTO_MODE = Continent, as uBlock Stripped
// Dynamic); the user edits only the added / removed TLDs. Auto-added TLDs on the HaGeZi
// abused-TLD list are dropped (SAFER_REGIONS_SKIP_ABUSED_TLDS); hand-added ones are kept.
// ─────────────────────────────────────────────────────────────────────────────

import { SAFE_ZONE_TLDS_CAP, SAFER_REGIONS_AUTO_MODE, SAFER_REGIONS_SKIP_ABUSED_TLDS, MANUAL_TLDS_CAP } from "../data/constants.js";
import { SPAM_TLDS } from "../data/spam-tlds.js";
import { rebuildTldList } from "./tld-engine.js";
import { isValidTld } from "../data/state-storage.js";

const ABUSED_TLDS = new Set(SPAM_TLDS);   // built once at module load

const AUTO_MODE = SAFER_REGIONS_AUTO_MODE;               // an AUTO_TLD_MODE value by construction (data/constants.js)

function browserTimeZone() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; }
  catch { return ""; }                                   // guard: Intl unavailable — no guess
}

async function acceptLanguages() {
  try { return (await chrome.i18n.getAcceptLanguages()) || []; }
  catch { return []; }
}

// Popup safer-regions editor: apply one edit to state.safeZone and recompute its list.
//   edit = { restoreDefault?: true, addTld?: string, removeTld?: string }
// Default = base TLDs + Continent (clears the user's added and removed TLDs). Adding a TLD also
// takes it off the removed list; removing one also takes it off the added list.
// (4.2.3: moved out of background.js — audit finding 6; behaviour unchanged.)
const LEADING_DOTS_RE = /^\.+/;
export async function editSaferRegions(safeZone, edit) {
  const z = safeZone;
  if (edit.restoreDefault) { z.manualTlds = []; z.excludedTlds = []; }
  if (typeof edit.addTld === "string") {
    const t = edit.addTld.trim().replace(LEADING_DOTS_RE, "").toLowerCase();
    if (!isValidTld(t)) throw new Error(`“${edit.addTld}” is not a valid TLD`);   // guard (audit finding 11)
    z.excludedTlds = z.excludedTlds.filter((x) => x !== t);
    if (!z.manualTlds.includes(t) && z.manualTlds.length < MANUAL_TLDS_CAP) z.manualTlds.push(t);
  }
  if (typeof edit.removeTld === "string") {
    z.manualTlds = z.manualTlds.filter((x) => x !== edit.removeTld);
    if (!z.excludedTlds.includes(edit.removeTld)) z.excludedTlds.push(edit.removeTld);
  }
  z.tlds = await computeSaferRegions(z);
}

export async function computeSaferRegions(safeZone) {
  const langs = await acceptLanguages();
  return new Promise((resolve) => {
    rebuildTldList(AUTO_MODE, langs, safeZone.manualTlds, safeZone.excludedTlds, (merged) => {
      const manual = new Set(safeZone.manualTlds || []);
      const kept = SAFER_REGIONS_SKIP_ABUSED_TLDS
        ? merged.filter((t) => manual.has(t) || !ABUSED_TLDS.has(t))
        : merged;
      resolve(kept.slice(0, SAFE_ZONE_TLDS_CAP));
    }, browserTimeZone());
  });
}
