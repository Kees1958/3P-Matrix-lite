// ── core/rule-builder.js ──────────────────────────────────────────────────────
// Pure DNR rule construction: state in, rule array out. No Chrome API calls.
//
// Public interface:
//   buildDynamicRules(state, opts) — Rule[] for chrome.declarativeNetRequest.updateDynamicRules
//     opts.cdnRegexSupported  boolean — use CDN_HOST_REGEX, else the looser "*cdn*" urlFilter
//   collectRegexes(rules)          — distinct regexFilter strings (for isRegexSupported checks)
//   buildSessionRules(state, tabsByLevel, highRiskTabIds, opts) — 4.4.5 tab band: Rule[] for
//     chrome.declarativeNetRequest.updateSessionRules. Per level 2–5 that has tabs: a reset allow
//     (cancels the session-level rules in those tabs) + the SAME protection / header / level /
//     Show Matrix rules, scoped by tabId instead of initiator, all at TAB_BAND_BASE + priority.
//     4.7.0: + a SECOND band for highRiskTabIds (tabs scored phishing this session) — only
//     alsoHighRisk protections, at HIGH_RISK_TAB_BASE + priority (data/protections.js, core/policy.js).
//   isLevelMechanismRule(rule)     — true for every rule EXCEPT the built-in whitelist allows and
//                                    Show Matrix overrides: what the level's own mechanism decides
//                                    (Show Matrix "Level mode" column, core/matrix-disposition.js)
//
// Rules are built per rule GROUP (core/policy.js ruleGroups): the global group
// excludes every locked site; each locked group covers only its own sites.
// Rule id = GROUP_ID_STRIDE * group.index + RULE_LOCAL_ID.*
// Group kinds (core/policy.js): global · locked (initiator-scoped) · tab (4.4.5, tabId-scoped session rules).
// Level 1 locks: one allowAllRequests rule per group (4.4.5) — the whole frame tree of the site is
// allowed, nested frames included, whatever the session level is.
//
// Priority model (data/constants.js PRIORITY, higher wins):
//   L5 code block  >  Show Matrix  >  security blocks (2,4,6,7)  >  L3 safer-regions allow
//   >  abused-TLD block (11)  >  built-in / CDN allow  >  L3/L4 level block
// 4.2: every level (3, 4, 5) targets third-party scripts + frames only (RT.CODE) — never
// images, video, fonts or stylesheets.
// ─────────────────────────────────────────────────────────────────────────────

import {
  LEVEL, GROUP_ID_STRIDE, RULE_LOCAL_ID as ID, PRIORITY, RT, PP_VALUE, SANDBOX_CSP_VALUE, CSP_NO_WS_VALUE,
  CDN_HOST_REGEX, CDN_URL_FILTER_FALLBACK, HTTP_URL_FILTER, IP_LITERAL_REGEX, NON_STANDARD_PORT_REGEX, BYETHOST_REGEX, BUILTIN_EXEMPT_LEVELS,
  WASM_URL_REGEX,
  MATRIX_RULE_ID_BASE, MATRIX_RULES_MAX, MATRIX_SCOPE, MATRIX_SCOPE_RESOURCE_TYPE, MATRIX_ACTION, MATRIX_SITE_ALL,
  TAB_BAND_RULES_MAX, LOG_PREFIX
} from "../data/constants.js";
import { ruleGroups, tabBandGroups, highRiskTabGroups, isProtectionActive, isProtectionEnabled, saferRegionsApply, GROUP_KIND, allowSitesOf } from "./policy.js";
import { ALLOW_CATEGORY } from "../data/allow-categories.js";
import { PROTECTION_KEY, PROTECTION_BY_KEY } from "../data/protections.js";
import { SPAM_TLDS, SPAM_TLD_EXCEPTIONS } from "../data/spam-tlds.js";
import { SUSPICIOUS_HOSTING_DOMAINS } from "../data/suspicious-hosting.js";
import { EXFIL_CHANNELS, EXFIL_GROUP } from "../data/exfil-channels.js";
import { BUILTIN_BOTH, BUILTIN_SCRIPT_ONLY, BUILTIN_FRAME_ONLY, BUILTIN_ALL } from "../data/builtin-domains.js";
import {
  HIGH_RISK_HOSTNAMES, LOCAL_NETWORK_NAME_DOMAINS, LOCAL_NETWORK_INITIATOR_EXEMPT,
  buildLocalNetworkIpv4Regex, buildLocalNetworkIpv6Regex
} from "../data/network-data.js";

const ARRAY_KEYS = new Set(["initiatorDomains", "excludedInitiatorDomains", "requestDomains", "excludedRequestDomains"]);

// ── Scope helpers ────────────────────────────────────────────────────────────
// Sub-resource rules are scoped by the PAGE that makes the request (initiator).
function subScope(group) {
  if (group.kind === GROUP_KIND.TAB) return { tabIds: group.tabIds };       // 4.4.5: everything in these tabs
  if (group.kind === GROUP_KIND.LOCKED) return { initiatorDomains: group.sites };
  return group.sites.length ? { excludedInitiatorDomains: group.sites } : {};
}
// Top-level header rules are scoped by the page's OWN domain (request).
function mainScope(group) {
  if (group.kind === GROUP_KIND.LOCKED) return { requestDomains: group.sites };
  return group.sites.length ? { excludedRequestDomains: group.sites } : {};
}
// Merges condition parts; domain arrays are concatenated and de-duplicated.
function cond(...parts) {
  const out = {};
  for (const part of parts) {
    for (const [k, v] of Object.entries(part || {})) {
      if (ARRAY_KEYS.has(k)) out[k] = [...new Set([...(out[k] || []), ...v])];
      else out[k] = v;
    }
  }
  return out;
}
// 5.1.3 — the allow list's category sites (Firewall for the network and header protections, Scam for the frames
// block): a rule for the PAGE itself (main_frame only) skips them as the request's domain; every other rule (what a
// page loads, frames included) skips requests those sites' pages start (excludedInitiatorDomains).
const MAIN_FRAME = "main_frame";
// The header rules that belong to Scam protection (blockRedirectsDialogs) — by local id (rule id % GROUP_ID_STRIDE).
const SCAM_HEADER_IDS = new Set([ID.HDR_CSP_SUB, ID.HDR_HIGH_RISK_CSP_SANDBOX]);
function withAllowExclusions(r, sites) {
  if (!sites.length) return r;
  const types = r.condition.resourceTypes || [];
  const pageOnly = types.length > 0 && types.every((t) => t === MAIN_FRAME);
  return { ...r, condition: cond(r.condition, pageOnly ? { excludedRequestDomains: sites } : { excludedInitiatorDomains: sites }) };
}

// group.priorityBase is TAB_BAND_BASE for the tab band, absent (0) for every dynamic group.
function rule(group, localId, priority, action, condition) {
  return { id: GROUP_ID_STRIDE * group.index + localId, priority: (group.priorityBase || 0) + priority, action, condition };
}
const BLOCK = Object.freeze({ type: "block" });
const ALLOW = Object.freeze({ type: "allow" });
function appendHeader(header, value) {
  return { type: "modifyHeaders", responseHeaders: [{ header, operation: "append", value }] };
}

// 4.6.0 — data exfiltration: one block rule per channel of `channelGroup` (data/exfil-channels.js), on every
// sub-resource request, except from the channel's own service. `pageScope` narrows which pages it applies to.
function exfilRules(group, channelGroup, pageScope) {
  return EXFIL_CHANNELS.filter((c) => c.group === channelGroup).map((c) =>
    rule(group, c.ruleLocalId, PRIORITY.SECURITY_BLOCK, BLOCK, cond(subScope(group), pageScope, {
      requestDomains: [...c.requestDomains], excludedInitiatorDomains: [...c.ownDomains], resourceTypes: [...RT.ALL_SUB],
      ...(c.urlFilter ? { urlFilter: c.urlFilter } : {})
    })));
}

// Pages exempt from an OUTSIDE_SAFER_REGIONS protection that is a REQUEST rule (scoped by the page = initiator):
// safer regions at SAFER_REGIONS_LEVELS (level 3) and the built-in whitelist at BUILTIN_EXEMPT_LEVELS (3, 4) —
// the same two exemptions headerRules() applies by the page's own domain.
function outsideSaferInitiators(L, safeTlds) {
  return cond(
    saferRegionsApply(L) && safeTlds.length ? { excludedInitiatorDomains: safeTlds } : {},
    BUILTIN_EXEMPT_LEVELS.includes(L) && BUILTIN_ALL.length ? { excludedInitiatorDomains: BUILTIN_ALL } : {}
  );
}

// 4.7.0 — shared by protectionRules()/headerRules(): for an ordinary group, the usual level gate;
// for a `highRiskOnly` group (core/policy.js highRiskTabGroups — this tab was scored phishing this
// session), ONLY a protection with alsoHighRisk runs, and it runs regardless of level/safer regions.
function onFor(state, group, L) {
  return (key) => {
    if (group.highRiskOnly) { const p = PROTECTION_BY_KEY[key]; return !!(p && p.alsoHighRisk) && isProtectionEnabled(state, key); }
    return isProtectionActive(state, key, L);
  };
}

// 4.7.0 — alsoHighRisk's STATIC half (data/network-data.js HIGH_RISK_HOSTNAMES — unconditional on
// level, same pattern as the pre-existing protection-9 HDR_HIGH_RISK rule): the hosts this GROUP
// covers (global = every high-risk host not locked elsewhere; locked = this group's own sites).
// 5.0.5 — blockWebsockets/blockWebtransport/blockWebAssembly as a network block, next to their page mechanism (CSP header / page script), which
// cannot reach a worker loaded from its own URL or a shared worker (tested: a third-party WebSocket and WebAssembly
// got through from both at level 4). One table for the level-gated rules and the static high-risk half.
const WASM_REQUEST = Object.freeze({ regexFilter: WASM_URL_REGEX, isUrlFilterCaseSensitive: false, resourceTypes: [...RT.WASM_FETCH] });
const NET_BLOCKS = Object.freeze([
  Object.freeze({ key: PROTECTION_KEY.BLOCK_WEBSOCKETS,   id: ID.NET_WS,   hrId: ID.NET_HIGH_RISK_WS,   match: Object.freeze({ resourceTypes: ["websocket"] }) }),
  Object.freeze({ key: PROTECTION_KEY.BLOCK_WEBTRANSPORT, id: ID.NET_WT,   hrId: ID.NET_HIGH_RISK_WT,   match: Object.freeze({ resourceTypes: ["webtransport"] }) }),
  Object.freeze({ key: PROTECTION_KEY.BLOCK_WEBASSEMBLY,  id: ID.NET_WASM, hrId: ID.NET_HIGH_RISK_WASM, match: WASM_REQUEST })
]);
const THIRD_PARTY = Object.freeze({ domainType: "thirdParty" });

function staticHighRiskHosts(group) {
  return group.kind === GROUP_KIND.LOCKED
    ? HIGH_RISK_HOSTNAMES.filter((h) => group.sites.includes(h))
    : group.kind === GROUP_KIND.GLOBAL ? HIGH_RISK_HOSTNAMES.filter((h) => !group.sites.includes(h)) : [];   // never for TAB groups — host-scoped, not tab-scoped
}

// ── Protection rules (DNR / header mechanisms) ───────────────────────────────
function protectionRules(state, group, safeTlds) {
  const L = group.level;
  const on = onFor(state, group, L);
  const sub = subScope(group);
  const rules = [];

  if (on(PROTECTION_KEY.BLOCK_WEB_BUNDLES)) {                                           // 2
    rules.push(rule(group, ID.WEBBUNDLE, PRIORITY.SECURITY_BLOCK, BLOCK, cond(sub, { resourceTypes: ["webbundle"] })));
  }
  if (on(PROTECTION_KEY.BLOCK_LOCAL_NETWORK)) {                                         // 4
    const base = cond(sub, { domainType: "thirdParty", resourceTypes: [...RT.ALL_SUB], excludedInitiatorDomains: [...LOCAL_NETWORK_INITIATOR_EXEMPT] });
    rules.push(rule(group, ID.LOCALNET_NAMES, PRIORITY.LOCALNET_BLOCK, BLOCK, cond(base, { requestDomains: [...LOCAL_NETWORK_NAME_DOMAINS] })));
    rules.push(rule(group, ID.LOCALNET_IPV4,  PRIORITY.LOCALNET_BLOCK, BLOCK, cond(base, { regexFilter: buildLocalNetworkIpv4Regex(), isUrlFilterCaseSensitive: false })));
    rules.push(rule(group, ID.LOCALNET_IPV6,  PRIORITY.LOCALNET_BLOCK, BLOCK, cond(base, { regexFilter: buildLocalNetworkIpv6Regex(), isUrlFilterCaseSensitive: false })));
  }
  if (on(PROTECTION_KEY.BLOCK_SUSPICIOUS_3P)) {                                         // 6
    const tp = cond(sub, { domainType: "thirdParty" });
    rules.push(rule(group, ID.SUSP_IP,         PRIORITY.SECURITY_BLOCK, BLOCK, cond(tp, { regexFilter: IP_LITERAL_REGEX, isUrlFilterCaseSensitive: false })));
    rules.push(rule(group, ID.SUSP_PORT_BLOCK, PRIORITY.SECURITY_BLOCK, BLOCK, cond(tp, { regexFilter: NON_STANDARD_PORT_REGEX, isUrlFilterCaseSensitive: false })));
    rules.push(rule(group, ID.SUSP_HOSTING,    PRIORITY.SECURITY_BLOCK, BLOCK, cond(tp, { requestDomains: [...SUSPICIOUS_HOSTING_DOMAINS], resourceTypes: [...RT.CODE_AND_LIVE] })));  // Kees1958 hard block — see data/suspicious-hosting.js header for why this is a separate ingestion from HostList's own Kees1958 risk-score entries
    rules.push(rule(group, ID.SUSP_HOSTING_REGEX, PRIORITY.SECURITY_BLOCK, BLOCK, cond(tp, { regexFilter: BYETHOST_REGEX, isUrlFilterCaseSensitive: false, resourceTypes: [...RT.CODE_AND_LIVE] })));
  }
  if (on(PROTECTION_KEY.BLOCK_3P_HTTP)) {                                               // 7
    rules.push(rule(group, ID.HTTP_3P, PRIORITY.SECURITY_BLOCK, BLOCK, cond(sub, { urlFilter: HTTP_URL_FILTER, domainType: "thirdParty", resourceTypes: [...RT.ALL_SUB] })));
  }
  // 10: 3P scripts and frames from abused TLDs, every level ≥ 2. Level 5 skips it — its own
  // code block (higher priority, no exceptions) already covers every such request.
  // 5.0.5 (user decision): at levels 2–3 also their WebSocket/WebTransport connections; from level 4 protections
  // 31/32 block every third-party one anyway (also as a network rule since 5.0.5), so 4 keeps scripts/frames only.
  if (on(PROTECTION_KEY.BLOCK_ABUSED_TLDS) && L !== LEVEL.STRICT) {
    rules.push(rule(group, ID.SPAM_TLD_BLOCK, PRIORITY.SPAM_TLD_BLOCK, BLOCK,
      cond(sub, { domainType: "thirdParty", requestDomains: [...SPAM_TLDS], excludedRequestDomains: [...SPAM_TLD_EXCEPTIONS],
                  resourceTypes: [...(L < LEVEL.HIGH ? RT.CODE_AND_LIVE : RT.CODE)] })));
  }
  // 28 (5.0.5): 3P WebAssembly from a dubious host (any TLD) OR from outside the safer regions. Source-based (the
  // requested host), so it applies on every page; a network rule, so it holds inside workers too. The safer-region
  // TLDs and the built-in whitelist exempt the REQUESTED host at the levels where they apply (as for 3P scripts).
  if (on(PROTECTION_KEY.BLOCK_WASM_DUBIOUS)) {
    const wasm = cond(sub, THIRD_PARTY, WASM_REQUEST);
    rules.push(rule(group, ID.WASM_DUBIOUS_HOST, PRIORITY.SECURITY_BLOCK, BLOCK, cond(wasm, { requestDomains: [...SUSPICIOUS_HOSTING_DOMAINS] })));
    rules.push(rule(group, ID.WASM_DUBIOUS_TLD,  PRIORITY.SECURITY_BLOCK, BLOCK, cond(wasm, { requestDomains: [...SPAM_TLDS], excludedRequestDomains: [...SPAM_TLD_EXCEPTIONS] })));
    rules.push(rule(group, ID.WASM_OUTSIDE_SAFER, PRIORITY.SECURITY_BLOCK, BLOCK, cond(wasm,
      saferRegionsApply(L) && safeTlds.length ? { excludedRequestDomains: safeTlds } : {},
      BUILTIN_EXEMPT_LEVELS.includes(L) && BUILTIN_ALL.length ? { excludedRequestDomains: BUILTIN_ALL } : {})));
  }
  // 31–33 (5.0.5): the network half of the level-4–5 blocks (NET_BLOCKS above) — same exemptions as their page half
  // (outside safer regions, built-in whitelist at its levels), scoped by the requester so a worker counts as its page.
  const netScope = cond(sub, outsideSaferInitiators(L, safeTlds), THIRD_PARTY);
  for (const b of NET_BLOCKS) if (on(b.key)) rules.push(rule(group, b.id, PRIORITY.SECURITY_BLOCK, BLOCK, cond(netScope, b.match)));
  if (on(PROTECTION_KEY.BLOCK_EXFIL_MESSAGING_BOTS)) rules.push(...exfilRules(group, EXFIL_GROUP.MESSAGING_BOTS, {}));        // every site
  if (on(PROTECTION_KEY.BLOCK_EXFIL_WEB_SERVICES)) {                                                                          // outside safer regions
    rules.push(...exfilRules(group, EXFIL_GROUP.WEB_SERVICES, outsideSaferInitiators(L, safeTlds)));
  }
  // 4.7.0 — alsoHighRisk STATIC half (not gated by L/safer regions): the PAGE is one of the fixed
  // high-risk hosts, so blockExfilWebServices applies to it regardless of the slider. Own rule ids
  // (EXFIL_FORM_MAIL_HR/EXFIL_AUTOMATION_HR) — exfilRules()'s own ids already belong to the ordinary
  // (level-gated) rule above and would collide if reused with a different condition in the same group.
  if (!group.highRiskOnly && isProtectionEnabled(state, PROTECTION_KEY.BLOCK_EXFIL_WEB_SERVICES) && PROTECTION_BY_KEY[PROTECTION_KEY.BLOCK_EXFIL_WEB_SERVICES].alsoHighRisk) {
    const hrHosts = staticHighRiskHosts(group);
    const HR_LOCAL_ID = Object.freeze({ [ID.EXFIL_FORM_MAIL]: ID.EXFIL_FORM_MAIL_HR, [ID.EXFIL_AUTOMATION]: ID.EXFIL_AUTOMATION_HR });
    if (hrHosts.length) {
      // hrHosts is already the exact scope (the high-risk subset of THIS group's sites, or of every
      // unlocked site for the global group) — built standalone, not merged through subScope(group)'s
      // own domain lists, which would union initiatorDomains back up to the whole lock group.
      rules.push(...EXFIL_CHANNELS.filter((c) => c.group === EXFIL_GROUP.WEB_SERVICES).map((c) =>
        rule(group, HR_LOCAL_ID[c.ruleLocalId], PRIORITY.SECURITY_BLOCK, BLOCK, {
          initiatorDomains: hrHosts,
          requestDomains: [...c.requestDomains], excludedInitiatorDomains: [...c.ownDomains], resourceTypes: [...RT.ALL_SUB],
          ...(c.urlFilter ? { urlFilter: c.urlFilter } : {})
        })));
    }
  }
  // 5.0.5 — static high-risk half of 31–33 (the page is a fixed high-risk host: active regardless of level), next to
  // blockWebsockets's HDR_HIGH_RISK_CSP_WS. Standalone scope, as for the exfil rules above.
  if (!group.highRiskOnly) {
    const hrHosts = staticHighRiskHosts(group);
    if (hrHosts.length) {
      for (const b of NET_BLOCKS) {
        if (isProtectionEnabled(state, b.key) && PROTECTION_BY_KEY[b.key].alsoHighRisk)
          rules.push(rule(group, b.hrId, PRIORITY.SECURITY_BLOCK, BLOCK, cond({ initiatorDomains: hrHosts }, THIRD_PARTY, b.match)));
      }
    }
  }
  return rules.map((r) => withAllowExclusions(r, allowSitesOf(state, ALLOW_CATEGORY.FIREWALL)));   // 5.1.3: Firewall sites
}

// 4.7.0 — the ordinary tab band (level-lock) deliberately skips main_frame here (see withMain below):
// its site is ALSO covered by the dynamic LOCKED group's own requestDomains-scoped main_frame rule, so
// adding it again here would duplicate the header. The highRiskOnly band has no such locked-group
// twin — a dynamically-flagged (not statically listed) site is never in any requestDomains condition —
// so it needs its OWN tabIds-scoped main_frame condition instead of the ordinary mainScope(group).
function hrMainScope(group) { return group.highRiskOnly ? { tabIds: group.tabIds } : mainScope(group); }

// ── Header rules (blockScpPrivacy/blockScpSecurity, blockRedirectsDialogs, blockWebsockets) ─────────────────────────────────
function headerRules(state, group, safeTlds) {
  const firewallSites = allowSitesOf(state, ALLOW_CATEGORY.FIREWALL);   // 5.1.3
  const scamSites = allowSitesOf(state, ALLOW_CATEGORY.SCAM);
  const L = group.level;
  const on = onFor(state, group, L);
  const rules = [];
  // Two independent exemptions from blockScpPrivacy/blockScpSecurity/blockSensorsNfc/blockRedirectsDialogs, merged (cond() unions the domain
  // arrays): safer regions (TLD list, level 3 only — levels 4–5 deliberately ignore it) and the
  // built-in whitelist (0.2.4: same levels as its 3P content allow, 3 and 4, never 5 — user
  // request: a built-in host is trusted on a FIRST-PARTY visit too, not just as a 3P embed).
  const outsideSafe = cond(
    saferRegionsApply(L) && safeTlds.length ? { excludedRequestDomains: safeTlds } : {},
    BUILTIN_EXEMPT_LEVELS.includes(L) && BUILTIN_ALL.length ? { excludedRequestDomains: BUILTIN_ALL } : {}
  );

  // 15–17: one combined Permissions-Policy value (outside safer regions at level 3).
  const pp = [];
  if (on(PROTECTION_KEY.BLOCK_SCP_PRIVACY))  pp.push(PP_VALUE.PRIVACY);
  if (on(PROTECTION_KEY.BLOCK_SCP_SECURITY)) pp.push(PP_VALUE.SECURITY);
  // Tab band: the top-level page's own headers come from the dynamic locked group (requestDomains),
  // so the band carries the frame (sub_frame) rules only — a header is never appended twice.
  // 4.7.0: the highRiskOnly band has no locked-group twin (see hrMainScope above) — it carries main_frame too.
  const withMain = group.kind !== GROUP_KIND.TAB || group.highRiskOnly;
  if (pp.length) {
    const action = appendHeader("Permissions-Policy", pp.join(", "));
    if (withMain) rules.push(rule(group, ID.HDR_PP_MAIN, PRIORITY.HEADERS, action, cond(hrMainScope(group), outsideSafe, { resourceTypes: ["main_frame"] })));
    rules.push(rule(group, ID.HDR_PP_SUB,  PRIORITY.HEADERS, action, cond(subScope(group),  outsideSafe, { resourceTypes: ["sub_frame"] })));
  }
  // blockRedirectsDialogs: sandbox CSP on FRAMES (outside safer regions at level 3). 5.1.3 (owner): no longer on the
  // top page — a sandboxed top page loses its own "Leave site?" prompt, print() and dialogs, and its popups inherit
  // the sandbox; top-page dialog spam is Scam protection's dialog part (every site from level 2).
  if (on(PROTECTION_KEY.BLOCK_REDIRECTS_DIALOGS)) {
    const action = appendHeader("Content-Security-Policy", SANDBOX_CSP_VALUE);
    rules.push(rule(group, ID.HDR_CSP_SUB,  PRIORITY.HEADERS, action, cond(subScope(group),  outsideSafe, { resourceTypes: ["sub_frame"] })));
  }
  // 4.7.0 — 29: WebSocket-blocking CSP (level 4–5 only — see PROTECTION_GROUPS' third entry; outsideSafe is
  // always {} there, since saferRegionsApply(L) is false from level 4 up, so this runs on every site once
  // active, same as the Permissions-Policy/sandbox rules above). A second rule here for blockInlineScripts (strict
  // script-src CSP) was
  // removed in 4.7.6 — see data/protections.js for why.
  if (on(PROTECTION_KEY.BLOCK_WEBSOCKETS)) {
    const action = appendHeader("Content-Security-Policy", CSP_NO_WS_VALUE);
    if (withMain) rules.push(rule(group, ID.HDR_CSP_WS_MAIN, PRIORITY.HEADERS, action, cond(hrMainScope(group), outsideSafe, { resourceTypes: ["main_frame"] })));
    rules.push(rule(group, ID.HDR_CSP_WS_SUB, PRIORITY.HEADERS, action, cond(subScope(group), outsideSafe, { resourceTypes: ["sub_frame"] })));
    // 5.0.5 — and on script responses the page requests (scoped by that page, the requester): a worker takes its
    // CSP from its own script, so this is what reaches a shared worker — Chrome does not show a shared worker's
    // WebSocket to extensions at all (tested), so the network rule (ID.NET_WS) cannot. Ordinary scripts ignore it.
    rules.push(rule(group, ID.HDR_CSP_WS_SCRIPT, PRIORITY.HEADERS, action, cond(subScope(group), outsideSaferInitiators(L, safeTlds), { resourceTypes: ["script"] })));
  }
  // (5.1.3: the former blockHighRiskEval rule here — privacy + security Permissions-Policy on high-risk sites — is gone
  // with that protection; blockScpPrivacy/-Security's alsoHighRisk rules below give the same headers there.)
  // 4.7.0 — alsoHighRisk STATIC half (17/18/19/21/29): a fixed high-risk host gets these headers
  // regardless of level/safer regions. Never for a TAB group — host-scoped (requestDomains), not
  // tab-scoped; the highRiskOnly TAB group already got the DYNAMIC half above via onFor()'s override.
  if (group.kind !== GROUP_KIND.TAB) {
    const hrHosts = staticHighRiskHosts(group);
    if (hrHosts.length) {
      const hrCond = { requestDomains: hrHosts, resourceTypes: ["main_frame", "sub_frame"] };
      const hrPp = [];
      if (isProtectionEnabled(state, PROTECTION_KEY.BLOCK_SCP_PRIVACY)  && PROTECTION_BY_KEY[PROTECTION_KEY.BLOCK_SCP_PRIVACY].alsoHighRisk)  hrPp.push(PP_VALUE.PRIVACY);
      if (isProtectionEnabled(state, PROTECTION_KEY.BLOCK_SCP_SECURITY) && PROTECTION_BY_KEY[PROTECTION_KEY.BLOCK_SCP_SECURITY].alsoHighRisk) hrPp.push(PP_VALUE.SECURITY);
      if (hrPp.length) rules.push(rule(group, ID.HDR_HIGH_RISK_PP, PRIORITY.HEADERS, appendHeader("Permissions-Policy", hrPp.join(", ")), hrCond));
      if (isProtectionEnabled(state, PROTECTION_KEY.BLOCK_REDIRECTS_DIALOGS) && PROTECTION_BY_KEY[PROTECTION_KEY.BLOCK_REDIRECTS_DIALOGS].alsoHighRisk)
        rules.push(rule(group, ID.HDR_HIGH_RISK_CSP_SANDBOX, PRIORITY.HEADERS, appendHeader("Content-Security-Policy", SANDBOX_CSP_VALUE),
          { ...hrCond, resourceTypes: ["sub_frame"] }));                              // 5.1.3: frames only, as above
      if (isProtectionEnabled(state, PROTECTION_KEY.BLOCK_WEBSOCKETS) && PROTECTION_BY_KEY[PROTECTION_KEY.BLOCK_WEBSOCKETS].alsoHighRisk) {
        rules.push(rule(group, ID.HDR_HIGH_RISK_CSP_WS, PRIORITY.HEADERS, appendHeader("Content-Security-Policy", CSP_NO_WS_VALUE), hrCond));
        rules.push(rule(group, ID.HDR_HIGH_RISK_CSP_WS_SCRIPT, PRIORITY.HEADERS, appendHeader("Content-Security-Policy", CSP_NO_WS_VALUE),
          { initiatorDomains: hrHosts, resourceTypes: ["script"] }));                       // 5.0.5 — see HDR_CSP_WS_SCRIPT
      }
      // BLOCK_INLINE_SCRIPTS's alsoHighRisk rule (HDR_HIGH_RISK_CSP_STRICT) removed in 4.7.6 along with the
      // protection itself — see data/protections.js.
    }
  }
  // 5.1.3: the frames block belongs to Scam protection, the rest to the Firewall — each skips its allow-list sites.
  return rules.map((r) => withAllowExclusions(r, SCAM_HEADER_IDS.has(r.id % GROUP_ID_STRIDE) ? scamSites : firewallSites));
}

// ── Level (third-party) rules ────────────────────────────────────────────────
function builtinAllowRules(group) {
  const sub = subScope(group);
  const tp = { domainType: "thirdParty" };
  const out = [];
  if (BUILTIN_BOTH.length)        out.push(rule(group, ID.BUILTIN_ALLOW_BOTH,   PRIORITY.BUILTIN_ALLOW, ALLOW, cond(sub, tp, { requestDomains: [...BUILTIN_BOTH],        resourceTypes: [...RT.CODE] })));
  if (BUILTIN_SCRIPT_ONLY.length) out.push(rule(group, ID.BUILTIN_ALLOW_SCRIPT, PRIORITY.BUILTIN_ALLOW, ALLOW, cond(sub, tp, { requestDomains: [...BUILTIN_SCRIPT_ONLY], resourceTypes: ["script"] })));
  if (BUILTIN_FRAME_ONLY.length)  out.push(rule(group, ID.BUILTIN_ALLOW_FRAME,  PRIORITY.BUILTIN_ALLOW, ALLOW, cond(sub, tp, { requestDomains: [...BUILTIN_FRAME_ONLY],  resourceTypes: ["sub_frame"] })));
  return out;
}

function levelRules(group, safeTlds, opts) {
  const L = group.level;
  const sub = subScope(group);
  const tp = { domainType: "thirdParty" };
  const rules = [];
  if (L < LEVEL.MILD) return rules;

  if (L === LEVEL.STRICT) {                                              // L5: scripts + frames, no exceptions
    rules.push(rule(group, ID.L5_BLOCK_CODE, PRIORITY.STRICT_BLOCK, BLOCK, cond(sub, tp, { resourceTypes: [...RT.CODE] })));
    return rules;
  }
  // (L2+ abused-TLD block = blockAbusedTlds, built in protectionRules.)

  if (L === LEVEL.SMART) {
    rules.push(rule(group, ID.L3_BLOCK_CODE, PRIORITY.LEVEL_BLOCK, BLOCK, cond(sub, tp, { resourceTypes: [...RT.CODE] })));
    if (saferRegionsApply(L) && safeTlds.length) {
      rules.push(rule(group, ID.SAFEZONE_ALLOW, PRIORITY.SAFEZONE_ALLOW, ALLOW, cond(sub, tp, { requestDomains: safeTlds, resourceTypes: [...RT.CODE] })));
    }
    rules.push(...builtinAllowRules(group));
  }

  if (L === LEVEL.HIGH) {
    rules.push(rule(group, ID.L4_BLOCK_CODE, PRIORITY.LEVEL_BLOCK, BLOCK, cond(sub, tp, { resourceTypes: [...RT.CODE] })));
    const cdnMatch = opts.cdnRegexSupported
      ? { regexFilter: CDN_HOST_REGEX, isUrlFilterCaseSensitive: false }
      : { urlFilter: CDN_URL_FILTER_FALLBACK };
    rules.push(rule(group, ID.CDN_ALLOW, PRIORITY.CDN_ALLOW, ALLOW, cond(sub, tp, cdnMatch, { resourceTypes: [...RT.CODE] })));
    rules.push(...builtinAllowRules(group));
  }
  return rules;
}

// ── Show Matrix overrides (always global — every site) ───────────────────────
// Script → resource type "script" from `domain`; Frame → "sub_frame" (4.2: two independent
// columns; disjoint types, so they never compete and share one priority). No initiatorDomains
// filter: an override applies on every first-party site (uMatrix / 3P-Matrix-lite model).
// PRIORITY.MATRIX outranks every level/security rule; only the L5 code block (higher) beats
// it, which is how "no matrix allows at level 5" is enforced.
// group = the tab-band group when the overrides must also hold inside a banded tab (4.4.5): the
// reset allow of the band outranks the global Show Matrix rules, so the band carries its own copy
// (tabIds scope, TAB_BAND_BASE priority, ids in the group's own sub-band — session ids are their own space).
export function buildMatrixRules(state, group = null) {
  const rules = [];
  const overrides = state.matrixRules[MATRIX_SITE_ALL] || {};
  const idBase = MATRIX_RULE_ID_BASE + (group ? group.index * MATRIX_RULES_MAX : 0);
  const priority = (group ? group.priorityBase : 0) + PRIORITY.MATRIX;
  let n = 0;
  for (const [domain, entry] of Object.entries(overrides)) {
    for (const scope of Object.values(MATRIX_SCOPE)) {
      const action = entry[scope];
      if (action !== MATRIX_ACTION.BLOCK && action !== MATRIX_ACTION.ALLOW) continue;
      if (n >= MATRIX_RULES_MAX) return rules;                      // guard: never overflow the band
      const condition = { requestDomains: [domain], domainType: "thirdParty", resourceTypes: [MATRIX_SCOPE_RESOURCE_TYPE[scope]] };
      if (group) condition.tabIds = group.tabIds;
      rules.push({ id: idBase + n, priority, action: { type: action }, condition });
      n++;
    }
  }
  return rules;
}

// ── Level 1 lock: allowAllRequests (4.4.5) ───────────────────────────────────
// Scoped by the page's OWN domain (requestDomains + main_frame): Chrome then allows every request of
// that page's frame tree — the nested frames' requests too, which an initiator-scoped rule never saw.
function allowAllRules(group) {
  if (group.kind !== GROUP_KIND.LOCKED || group.level !== LEVEL.ALLOW_ALL || !group.sites.length) return [];
  return [rule(group, ID.ALLOW_ALL_REQUESTS, PRIORITY.ALLOW_ALL_REQUESTS, { type: "allowAllRequests" },
    { requestDomains: [...group.sites], resourceTypes: ["main_frame"] })];
}

// ── Public ───────────────────────────────────────────────────────────────────
export function buildDynamicRules(state, opts = {}) {
  const safeTlds = state.safeZone.tlds.slice();
  const rules = [];
  for (const group of ruleGroups(state)) {
    if (group.level < LEVEL.MILD) { rules.push(...allowAllRules(group)); continue; }   // L1 = no block rules; a locked L1 site is allowed outright
    rules.push(...protectionRules(state, group, safeTlds));
    rules.push(...headerRules(state, group, safeTlds));
    rules.push(...levelRules(group, safeTlds, opts));
  }
  rules.push(...buildMatrixRules(state));
  return rules;
}

// ── Tab band (4.4.5) — session rules ─────────────────────────────────────────
// tabsByLevel: Map<level, tabId[]> from core/tab-locks.js. Returns [] when no tab is banded.
// Guard: more than TAB_BAND_RULES_MAX rules → none at all (a half band would let the reset allow
// cancel rules that are then missing); the caller falls back to the initiator-scoped locked groups.
export function buildSessionRules(state, tabsByLevel, highRiskTabIds = [], opts = {}) {
  const safeTlds = state.safeZone.tlds.slice();
  const rules = [];
  for (const group of tabBandGroups(tabsByLevel)) {
    rules.push(rule(group, ID.TAB_RESET, 0, ALLOW, { tabIds: group.tabIds, resourceTypes: [...RT.ALL_SUB] }));
    rules.push(...protectionRules(state, group, safeTlds));
    rules.push(...headerRules(state, group, safeTlds));
    rules.push(...levelRules(group, safeTlds, opts));
    rules.push(...buildMatrixRules(state, group));
  }
  // 4.7.0 — the high-risk band: ONLY alsoHighRisk protections (onFor()'s highRiskOnly override), no
  // reset-allow (nothing here switches the tab's level, it only adds to whatever already applies),
  // no level/third-party rules, no Show Matrix (unrelated to this escalation).
  for (const group of highRiskTabGroups(highRiskTabIds)) {
    rules.push(...protectionRules(state, group, safeTlds));
    rules.push(...headerRules(state, group, safeTlds));
  }
  if (rules.length > TAB_BAND_RULES_MAX) {
    console.warn(LOG_PREFIX, `tab band needs ${rules.length} rules (> ${TAB_BAND_RULES_MAX}) — not applied`);
    return [];
  }
  return rules;
}

const BUILTIN_ALLOW_LOCAL_IDS = new Set([ID.BUILTIN_ALLOW_SCRIPT, ID.BUILTIN_ALLOW_FRAME, ID.BUILTIN_ALLOW_BOTH]);
export function isLevelMechanismRule(r) {
  return r.id < MATRIX_RULE_ID_BASE && !BUILTIN_ALLOW_LOCAL_IDS.has(r.id % GROUP_ID_STRIDE);
}

export function collectRegexes(rules) {
  return [...new Set(rules.map((r) => r.condition.regexFilter).filter(Boolean))];
}
