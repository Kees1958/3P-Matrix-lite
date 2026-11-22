// ── data/settings-io.js ───────────────────────────────────────────────────────
// Pure conversion between the internal state and the human-readable settings
// backup file (Options → Save settings / Restore settings). No Chrome calls.
//
// Public interface:
//   toSettingsFile(state, extVersion)  — readable backup object (format v2)
//   fromSettingsFile(obj)              — raw state-shaped object (normalize afterwards!)
//                                        accepts format v2 (the v1 files of 0.1.x/0.2.0 are no
//                                        longer read since 4.5.4: "settings section missing")
//   summarize(state)                   — one line for the status message
//
// Format v2 sections (plain names, so a person can read and check the file):
//   startupLevel · protections.disabled · saferRegions{addedTlds, removedTlds, activeTlds} ·
//   allowList · lockedSites · showMatrixRules · onlineChecks · downloads (4.3.0)
// stateSchema (4.3.2) = the state schema the file was written with (see fromSettingsFile).
// downloads = warnRiskyDownloads's settings INCLUDING the VirusTotal API key (4.4.1, owner's decision: a backup
// must restore a working setup on another machine). THE BACKUP FILE IS PLAIN TEXT AND NOW CONTAINS A SECRET —
// keep it as private as the key itself. Restoring a file WITHOUT a key (≤ 4.4.0, or one written before a key
// was set) keeps the key already in this browser (background.js MSG_IMPORT_SETTINGS). Files from 4.2.x have
// no downloads section at all: defaults apply.
// 0.2.4: saferRegions.autoAddCountryCodes is no longer written (the auto-add scope is fixed);
// it is ignored when an older file is restored.
// showMatrixRules shape: { "*": { [domain]: { script?, frame? } } } — "*" (MATRIX_SITE_ALL) means
// "every site"; overrides are always global (uMatrix / 3P-Matrix-lite model). 4.2.3: a file with
// per-site keys (0.2.x) still restores — normalizeState() merges those rules into "*".
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, STATE_SCHEMA_VERSION } from "./constants.js";
import { PROTECTIONS } from "./protections.js";

export const SETTINGS_FORMAT = "3p-matrix-settings";
export const SETTINGS_FORMAT_VERSION = 2;

export function toSettingsFile(state, extVersion) {
  const allowList = state.siteLocksOrder.filter((s) => state.siteLocks[s] === LEVEL.ALLOW_ALL);
  const lockedSites = {};
  for (const s of state.siteLocksOrder) if (state.siteLocks[s] !== LEVEL.ALLOW_ALL) lockedSites[s] = state.siteLocks[s];
  return {
    format: SETTINGS_FORMAT,
    formatVersion: SETTINGS_FORMAT_VERSION,
    extensionVersion: extVersion,
    stateSchema: STATE_SCHEMA_VERSION,                    // 4.3.2: restore runs only the migrations this file still needs
    savedAt: new Date().toISOString(),
    settings: {
      startupLevel: state.startupLevel,
      protections: { disabled: Object.keys(state.disabledProtections) },
      saferRegions: {
        addedTlds: state.safeZone.manualTlds.slice(),
        removedTlds: state.safeZone.excludedTlds.slice(),
        activeTlds: state.safeZone.tlds.slice()          // informational — recomputed on restore
      },
      allowList,                                          // sites locked at level 1
      lockedSites,                                        // sites locked at levels 2–5
      showMatrixRules: JSON.parse(JSON.stringify(state.matrixRules)),
      onlineChecks: { firstDns: state.dns.first, secondDns: state.dns.second },
      downloads: JSON.parse(JSON.stringify(state.downloads))     // 4.4.1: the VirusTotal key is included
    }
  };
}

export function fromSettingsFile(obj) {
  if (!obj || obj.format !== SETTINGS_FORMAT) throw new Error("not a 3P Matrix settings file");
  const s = obj.settings;
  if (!s || typeof s !== "object") throw new Error("settings section missing");
  const siteLocks = {};
  const order = [];
  for (const site of Array.isArray(s.allowList) ? s.allowList : []) { siteLocks[site] = LEVEL.ALLOW_ALL; order.push(site); }
  for (const [site, lvl] of Object.entries(s.lockedSites || {})) { siteLocks[site] = lvl; order.push(site); }
  const disabled = {};
  for (const key of (s.protections && Array.isArray(s.protections.disabled)) ? s.protections.disabled : []) disabled[key] = true;
  const z = s.saferRegions || {};
  return {
    level: s.startupLevel, prevLevel: s.startupLevel, startupLevel: s.startupLevel,
    siteLocks, siteLocksOrder: order,
    disabledProtections: disabled,
    safeZone: { manualTlds: z.addedTlds, excludedTlds: z.removedTlds, tlds: z.activeTlds },
    dns: { first: s.onlineChecks && s.onlineChecks.firstDns, second: s.onlineChecks && s.onlineChecks.secondDns },
    matrixRules: s.showMatrixRules,
    downloads: s.downloads,
    // A file without stateSchema (≤ 4.3.1) counts as schema 1, so every migration runs on it — e.g. it
    // gets the 4.3.2 default-off protections unticked, exactly like a stored state from that time.
    schema: Number.isInteger(obj.stateSchema) ? obj.stateSchema : undefined
  };
}

export function summarize(state) {
  const allow = state.siteLocksOrder.filter((s) => state.siteLocks[s] === LEVEL.ALLOW_ALL).length;
  const locked = state.siteLocksOrder.length - allow;
  const matrix = Object.values(state.matrixRules).reduce((n, m) => n + Object.keys(m).length, 0);
  const off = Object.keys(state.disabledProtections).length;
  const z = state.safeZone;
  return `startup level ${state.startupLevel} · ${PROTECTIONS.length - off} of ${PROTECTIONS.length} protections on · ` +
    `${z.tlds.length} safer-region TLDs (${z.manualTlds.length} added, ${z.excludedTlds.length} removed) · ` +
    `${allow} allow-list sites · ${locked} locked sites · ${matrix} Show Matrix rules · ` +
    `${state.downloads.trustedDomains.length} trusted download domains`;
}
