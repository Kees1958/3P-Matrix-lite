// ── core/view-models.js ───────────────────────────────────────────────────────
// What each page receives from the service worker: one function per page, state in, plain data
// out (JSON-serializable, C31). Pages hold no business logic — they render these models.
// (4.2.3: moved out of background.js — audit finding 6; behaviour unchanged.)
//
// Public interface:
//   popupModel(state, tabId, url)   — Promise (4.5.4: awaits the badge restore) — popup (level, lock, bullets' counts, protections,
//                                     safer regions; 5.1.3: `page` — the "This page" box: site risk, tamper rating, Continue once)
//   firewallBlockCount(ruleIds)     — Promise<number> — 5.1.3: of the rules Chrome says matched in the tab (the popup's
//                                     getMatchedRules), how many are block rules (all of 3P Matrix's block rules are firewall)
//   matrixModel(state, tabId)       — Promise<Show Matrix panel model> (rows replayed through the
//                                     rules Chrome has — core/matrix-disposition.js)
//   optionsModel(state)             — options page (DNS choice, allow-list text, download protection —
//                                     4.3.0; the VirusTotal key itself never leaves the service worker)
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL_INFO, SEVERITY, DNS_PROVIDER, DNS_NONE, TAMPER_RATING, POPUP_RISK_REASONS_MAX, POPUP_MATCHED_RULES_MAX } from "../data/constants.js";
import { TAMPER_RATING_LABEL, TAMPER_RULE_BY_ID } from "../data/tamper-rules.js";
import { scoreLocal } from "./site-scorer.js";
import { isAllowedOnce } from "./navigation-guard.js";
import { pageRisk, pageFindings } from "./tamper-guard.js";
import { PROTECTION_GROUPS, PROTECTION_BY_KEY, protectionsInGroup } from "../data/protections.js";
import { effectiveLevel, lockedLevelOf, isProtectionTicked, protectionCounts, saferRegionsApply } from "./policy.js";
import { getCompiledRules, getCompiledModeRules } from "./apply-manager.js";
import { buildMatrixRows } from "./matrix-disposition.js";
import { globalMatrixOverrides } from "./matrix-overrides.js";
import { allowListText } from "./site-locks.js";
import { vtKeyIsSet } from "./download-settings.js";
import * as Badge from "./badge.js";
import * as Matrix from "./connection-matrix.js";
import { parseHttpUrl, registeredDomain, tldOf } from "../util/domain.js";

const DNS_NONE_LABEL = "None";

// 5.1.0: groups are per tab (g.tab). `enabled` = the user's own tick (the checkbox); `masterOff` = the tick stays,
// but its master protection (`requires`) is unticked, so it does nothing — the page greys it out and says why.
function protectionGroups(state, level) {
  return PROTECTION_GROUPS.map((g) => {
    const items = protectionsInGroup(g).filter((x) => x.switchable !== false)   // no checkbox of its own: not listed
      .map((x) => ({ key: x.key, num: x.num, label: x.label, description: x.description, enabled: isProtectionTicked(state, x.key),
                     masterOff: !!x.requires && !isProtectionTicked(state, x.requires),
                     masterLabel: x.requires ? PROTECTION_BY_KEY[x.requires].label : null }));
    return {
      tab: g.tab,
      title: !saferRegionsApply(level) && g.titleNoSaferRegions ? g.titleNoSaferRegions : g.title,
      fromLevel: g.fromLevel,
      active: items.filter((x) => x.enabled && !x.masterOff).length,   // protections in this group that work
      total: items.length,
      items
    };
  });
}

// 5.1.3 — the popup's "This page" box: only what there is to know (each part null / false when there is nothing).
//   risk      — the site check's verdict for the tab's site (core/badge.js keeps it per tab) with its top reasons
//   tamper    — the page's tamper rating when Suspicious or worse, how many findings, and (owner, 2026-11-24) the name
//               of the most serious one (`topLabel`, data/tamper-rules.js label) so the line says WHAT was found
//   continued — "Continue once" was chosen for this site in this tab (core/navigation-guard.js)
// The most serious finding's name (most points; on equal points the one found first).
function topFindingLabel(tabId) {
  const top = pageFindings(tabId).reduce((best, f) => (!best || f.points > best.points ? f : best), null);
  return top ? TAMPER_RULE_BY_ID[top.rule].label : "";
}

async function pageBox(tabId, url, p) {
  const stored = Badge.getRisk(tabId);
  const severity = stored && p && stored.site === registeredDomain(p.host) ? stored.severity : SEVERITY.NONE;
  const local = severity !== SEVERITY.NONE ? scoreLocal(url) : null;
  const risk = severity === SEVERITY.NONE ? null
    : { severity, reasons: local ? local.signals.slice(0, POPUP_RISK_REASONS_MAX) : [] };
  const t = pageRisk(tabId);
  const tamper = t && t.rating >= TAMPER_RATING.SUSPICIOUS
    ? { rating: t.rating, ratingLabel: TAMPER_RATING_LABEL[t.rating], findings: t.findings, topLabel: topFindingLabel(tabId) } : null;
  const continued = !!p && Number.isInteger(tabId) && await isAllowedOnce(tabId, registeredDomain(p.host));
  return { risk, tamper, continued };
}

// 4.5.4: async — waits until the badge's per-tab state is restored (core/badge.js ready()), so a popup
// that wakes the service worker still shows the site's risk.
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
    risk: (Badge.getRisk(tabId) || {}).severity || SEVERITY.NONE,
    page: await pageBox(tabId, url, p)                 // 5.1.3
  };
}

// 5.1.3 — every block rule of 3P Matrix belongs to the firewall (the level rules and the Firewall protection tab's DNR
// rules; Scam protection's frame rule is a header rule, Download and Tamper protection have no DNR rules). Header and
// allow rules are not counted. Ids are those the popup got from chrome.declarativeNetRequest.getMatchedRules.
export async function firewallBlockCount(ruleIds) {
  if (!Array.isArray(ruleIds)) return 0;
  const blocks = new Set((await getCompiledRules()).filter((r) => r.action === "block").map((r) => r.id));
  return ruleIds.slice(0, POPUP_MATCHED_RULES_MAX).filter((id) => blocks.has(id)).length;
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
    allowList: allowListText(state),                 // 5.1.3: "Category: domain" lines
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
    trustAppStores:     d.trustAppStores,          // 5.1.3: the "Trust app stores" tickbox
    warningColor:       { ...d.warningColor },
    warningTitle:       d.warningTitle
  };
}
