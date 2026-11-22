// ── core/view-models.js ───────────────────────────────────────────────────────
// What each page receives from the service worker: one function per page, state in, plain data
// out (JSON-serializable, C31). Pages hold no business logic — they render these models.
// (4.2.3: moved out of background.js — audit finding 6; behaviour unchanged.)
//
// Public interface:
//   popupModel(state, tabId, url)   — Promise (4.5.4: awaits the badge restore) — popup (level, lock, bullets' counts, protections, safer regions)
//   matrixModel(state, tabId)       — Promise<Show Matrix panel model> (rows replayed through the
//                                     rules Chrome has — core/matrix-disposition.js)
//   optionsModel(state)             — options page (DNS choice, allow-list text, download protection —
//                                     4.3.0; the VirusTotal key itself never leaves the service worker)
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL_INFO, SEVERITY, DNS_PROVIDER, DNS_NONE } from "../data/constants.js";
import { PROTECTION_GROUPS, protectionsInGroup } from "../data/protections.js";
import { effectiveLevel, lockedLevelOf, isProtectionEnabled, protectionCounts, saferRegionsApply } from "./policy.js";
import { getCompiledRules, getCompiledModeRules } from "./apply-manager.js";
import { buildMatrixRows } from "./matrix-disposition.js";
import { globalMatrixOverrides } from "./matrix-overrides.js";
import { allowListSites } from "./site-locks.js";
import { vtKeyIsSet } from "./download-settings.js";
import * as Badge from "./badge.js";
import * as Matrix from "./connection-matrix.js";
import { parseHttpUrl, registeredDomain, tldOf } from "../util/domain.js";

const DNS_NONE_LABEL = "None";
const ALLOW_LIST_SEPARATOR = "\n";

function protectionGroups(state, level) {
  return PROTECTION_GROUPS.map((g) => {
    const items = protectionsInGroup(g)
      .map((x) => ({ key: x.key, num: x.num, label: x.label, description: x.description, enabled: isProtectionEnabled(state, x.key) }));
    return {
      title: !saferRegionsApply(level) && g.titleNoSaferRegions ? g.titleNoSaferRegions : g.title,
      fromLevel: g.fromLevel,
      active: items.filter((x) => x.enabled).length,   // ticked protections in this group (popup bullets)
      total: items.length,
      items
    };
  });
}

// 4.5.4: async — waits until the badge's per-tab state is restored (core/badge.js ready()), so a popup
// that wakes the service worker still shows the real blocked count.
export async function popupModel(state, tabId, url) {
  await Badge.ready();
  const p = parseHttpUrl(url || "");
  const host = p ? p.host : "";
  const level = p ? effectiveLevel(state, host) : state.level;
  return {
    host,
    site: p ? registeredDomain(host) : "",
    scorable: !!p,
    inSafeZone: !!p && state.safeZone.tlds.includes(tldOf(host)),
    level, sessionLevel: state.level, startupLevel: state.startupLevel,
    lockedLevel: p ? lockedLevelOf(state, host) : null,
    levelInfo: LEVEL_INFO,
    saferRegionsRelevant: saferRegionsApply(level),   // safer-regions panel + IN/OUTSIDE label shown
    counts: protectionCounts(state, level),
    groups: protectionGroups(state, level),
    safeZone: { tlds: state.safeZone.tlds },
    blocked: Badge.getCount(tabId),
    risk: (Badge.getRisk(tabId) || {}).severity || SEVERITY.NONE
  };
}

// Observed rows (core/connection-matrix.js) + the policy's decision per row. Rows with an
// override but not seen (yet) are listed too, so an override can always be cleared from the panel.
export async function matrixModel(state, tabId) {
  const data = Matrix.getMatrixData(tabId);
  const overrides = globalMatrixOverrides(state);
  const entries = data.entries.slice();
  const seen = new Set(entries.map((e) => e.domain));
  for (const domain of Object.keys(overrides)) {
    if (!seen.has(domain)) entries.push({ domain, types: [], sampleUrls: {}, count: 0 });
  }
  const level = data.host ? effectiveLevel(state, data.host) : state.level;
  const [compiled, compiledMode] = await Promise.all([getCompiledRules(), getCompiledModeRules()]);
  const rows = buildMatrixRows({ entries, overrides, level, host: data.host, tabId, compiled, compiledMode });
  return { ...data, entries: rows, level, levelInfo: LEVEL_INFO };
}

// 4.7.0 — the Protections panel (ui/protections.html, a full tab: no "current site" exists there,
// unlike the popup) replaces ui/options.html. It needs the protections list too, so this model now
// carries it as well — the SAME protectionGroups()/protectionCounts() the popup uses, at the global
// state.level (there is no site to score a level FOR on this page).
export function optionsModel(state) {
  return {
    level: state.level,
    levelInfo: LEVEL_INFO,
    counts: protectionCounts(state, state.level),
    groups: protectionGroups(state, state.level),
    dns: state.dns,
    providers: [
      ...Object.values(DNS_PROVIDER).map((p) => ({ id: p.id, label: p.label, host: p.host })),
      { id: DNS_NONE, label: DNS_NONE_LABEL, host: "" }
    ],
    allowList: allowListSites(state).join(ALLOW_LIST_SEPARATOR),
    downloads: downloadsModel(state)
  };
}

function downloadsModel(state) {
  const d = state.downloads;
  return {
    vtKeySet:           vtKeyIsSet(state),
    vtEnabled:          d.vtEnabled,
    silentWhenInconclusive: d.silentWhenInconclusive,
    autoAllow:          d.autoAllow,
    autoAllowThreshold: d.autoAllowThreshold,
    fpReductionLevel:   d.fpReductionLevel,
    trustedDomains:     d.trustedDomains.slice(),
    warningColor:       { ...d.warningColor },
    warningTitle:       d.warningTitle
  };
}
