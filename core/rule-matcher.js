// ── core/rule-matcher.js ──────────────────────────────────────────────────────
// Pure re-implementation of declarativeNetRequest matching for OUR OWN dynamic
// rules, used to decide whether a request that Chrome reports as
// net::ERR_BLOCKED_BY_CLIENT was blocked by 3P Matrix (counted) or by another
// extension (not counted). No Chrome API calls.
//
// Public interface:
//   compileRules(rules)                 — precompile once per applied rule set
//   matchOutcome(compiled, request, topHost?) — { action: "block"|"allow"|null, ruleId }
//        request = { url, type, initiator, tabId? }   (webRequest details fields)
//        topHost = the tab's top-level host (core/tab-sites.js). Used (a) when the initiator is
//        opaque ("null") and (b) 4.4.5: by allowAllRequests rules (level-1 locks), which apply to the
//        whole frame tree of a page whatever frame the request comes from; it defaults to the
//        initiator's host (Show Matrix replays with the page as initiator). Rules carrying tabIds
//        (the 4.4.5 tab band) only match a request whose tabId is in the list. 4.2.1: Chrome matches such a request against the opaque origin's
//        precursor (the site that created the sandboxed / data: / srcdoc frame); webRequest
//        only reports "null", and treating it as "no initiator" (= first-party) made our own
//        blocks look like someone else's — Show Matrix then showed them as allowed.
//
// Semantics implemented (exactly the subset our rule builder emits):
//   resourceTypes (absent = every type except main_frame), domainType thirdParty,
//   initiatorDomains / excludedInitiatorDomains, requestDomains /
//   excludedRequestDomains (domain or any parent, so a TLD entry covers the TLD),
//   regexFilter (case-insensitive), urlFilter with | anchors and * wildcards.
//   tabIds (session rules), allowAllRequests (main_frame rule that decides on the TAB's host).
//   Highest priority wins; on equal priority "allow" beats "block" (Chrome's
//   documented action precedence). modifyHeaders rules never block — ignored.
// ─────────────────────────────────────────────────────────────────────────────

import { chromeSite } from "../util/domain.js";

const ALLOW_ALL_ACTION = "allowAllRequests";
const COUNTED_ACTIONS = new Set(["block", "allow", ALLOW_ALL_ACTION]);
const ACTION_RANK = Object.freeze({ allow: 2, [ALLOW_ALL_ACTION]: 2, block: 1 });   // tie-break at equal priority
const DEFAULT_EXCLUDED_TYPE = "main_frame";
const OPAQUE_INITIATOR = "null";                               // webRequest's text for an opaque origin

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, ""); } catch { return ""; }
}

// True when `host` or one of its parent domains is in `set`.
function domainIn(host, set) {
  if (!host || !set) return false;
  let h = host;
  for (;;) {
    if (set.has(h)) return true;
    const dot = h.indexOf(".");
    if (dot === -1) return false;
    h = h.slice(dot + 1);
  }
}

function urlFilterToRegExp(filter) {
  let src = filter;
  let head = "", tail = "";
  if (src.startsWith("|")) { head = "^"; src = src.slice(1); }
  if (src.endsWith("|"))   { tail = "$"; src = src.slice(0, -1); }
  const body = src.split("*").map((p) => p.replace(/[.+?^${}()[\]\\]/g, "\\$&").replace(/\|/g, "\\|")).join(".*");
  return new RegExp(head + body + tail, "i");
}

function toSet(arr) { return Array.isArray(arr) ? new Set(arr) : null; }

export function compileRules(rules) {
  const out = [];
  for (const r of rules || []) {
    if (!r || !r.action || !COUNTED_ACTIONS.has(r.action.type)) continue;
    const c = r.condition || {};
    out.push({
      id: r.id,
      priority: r.priority || 1,
      action: r.action.type === ALLOW_ALL_ACTION ? "allow" : r.action.type,
      allowAll: r.action.type === ALLOW_ALL_ACTION,
      rank: ACTION_RANK[r.action.type],
      tabIds: toSet(c.tabIds),
      types: toSet(c.resourceTypes),
      thirdParty: c.domainType === "thirdParty",
      firstParty: c.domainType === "firstParty",
      initiators: toSet(c.initiatorDomains),
      exInitiators: toSet(c.excludedInitiatorDomains),
      requests: toSet(c.requestDomains),
      exRequests: toSet(c.excludedRequestDomains),
      regex: c.regexFilter ? new RegExp(c.regexFilter, "i") : null,
      urlRe: c.urlFilter ? urlFilterToRegExp(c.urlFilter) : null
    });
  }
  // Highest priority first, allow before block at equal priority → first match wins.
  out.sort((a, b) => b.priority - a.priority || b.rank - a.rank);
  return out;
}

function ruleMatches(rule, req, reqHost, initHost, isThirdParty, topHost) {
  if (rule.tabIds && !rule.tabIds.has(req.tabId)) return false;                       // tab band: only its own tabs
  // allowAllRequests is a main_frame rule: it decides on the page the request belongs to (the tab's top host).
  if (rule.allowAll) return !!topHost && domainIn(topHost, rule.requests);
  if (rule.types ? !rule.types.has(req.type) : req.type === DEFAULT_EXCLUDED_TYPE) return false;
  if (rule.thirdParty && !isThirdParty) return false;
  if (rule.firstParty && isThirdParty) return false;
  if (rule.initiators && !domainIn(initHost, rule.initiators)) return false;
  if (rule.exInitiators && domainIn(initHost, rule.exInitiators)) return false;
  if (rule.requests && !domainIn(reqHost, rule.requests)) return false;
  if (rule.exRequests && domainIn(reqHost, rule.exRequests)) return false;
  if (rule.regex && !rule.regex.test(req.url)) return false;
  if (rule.urlRe && !rule.urlRe.test(req.url)) return false;
  return true;
}

export function matchOutcome(compiled, req, topHostArg = "") {
  const reqHost = hostOf(req.url);
  const topHostGiven = String(topHostArg || "").toLowerCase();
  const initHost = req.initiator === OPAQUE_INITIATOR ? topHostGiven
                 : req.initiator ? hostOf(req.initiator) : "";
  const topHost = topHostGiven || initHost;
  // No initiator (e.g. browser-initiated, or opaque with no stand-in) → DNR treats the request
  // as first-party.
  const isThirdParty = !!initHost && chromeSite(reqHost) !== chromeSite(initHost);
  for (const rule of compiled) {
    if (ruleMatches(rule, req, reqHost, initHost, isThirdParty, topHost)) return { action: rule.action, ruleId: rule.id };
  }
  return { action: null, ruleId: null };
}
