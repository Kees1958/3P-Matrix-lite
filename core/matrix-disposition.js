// ── core/matrix-disposition.js ────────────────────────────────────────────────
// Show Matrix row model (3P-Matrix-lite 4.0.2 model, 4.2.1): for every observed third-party row,
// what the policy DECIDES — not what happened to be observed. Pure: no Chrome API calls.
//
// Public interface:
//   buildMatrixRows(input) — rows for the panel
//     input = { entries, overrides, level, host, tabId, compiled, compiledMode }
//       entries      core/connection-matrix.js getMatrixData().entries
//       overrides    { [rowKey]: { script?, frame? } } (the global Show Matrix overrides)
//       level        effective level of the observed site
//       host         observed tab's top-level host (the initiator a request is matched with)
//       tabId        observed tab (4.4.5: the tab band's session rules only match their own tabs)
//       compiled     every active rule (core/apply-manager.js getCompiledRules)
//       compiledMode active rules minus built-in allows and overrides (getCompiledModeRules)
//
// Per row:
//   script / frame  { effective: "allow"|"block", overridden } — replayed through the SAME rules
//                   Chrome has (core/rule-matcher.js), so the panel can never disagree with the
//                   real decision; present when that type was seen or has an override
//   mode            "allow" | "block" | "grey" — the level's own mechanism for 3P scripts (abused
//                   TLDs, safer regions, cdn hosts, level 5 …); grey when something else decides
//                   (an override, or the built-in whitelist at a level where it applies)
//   whitelist       "green" | "grey" | "empty" — built-in whitelist entry; grey when overridden
//                   or when the whitelist does not apply at this level; category for the tooltip
// ─────────────────────────────────────────────────────────────────────────────

import { MATRIX_SCOPE, MATRIX_SCOPE_RESOURCE_TYPE, MATRIX_ACTION, BUILTIN_EXEMPT_LEVELS } from "../data/constants.js";
import { BUILTIN_ALL, BUILTIN_CATEGORY } from "../data/builtin-domains.js";
import { matchOutcome } from "./rule-matcher.js";
import { isInDomainList } from "../util/domain.js";

export const DISPOSITION = Object.freeze({ ALLOW: "allow", BLOCK: "block" });
export const MODE_STATE = Object.freeze({ ALLOW: "allow", BLOCK: "block", GREY: "grey" });
export const WHITELIST_STATE = Object.freeze({ GREEN: "green", GREY: "grey", EMPTY: "empty" });

// Observed-type label (data/constants.js MATRIX_TYPE_LABEL value) per override scope.
const SCOPE_TYPE_LABEL = Object.freeze({ [MATRIX_SCOPE.SCRIPT]: "script", [MATRIX_SCOPE.FRAME]: "frame" });
const MODE_SCOPE = MATRIX_SCOPE.SCRIPT;          // Level mode = the level's decision for 3P scripts
const SAMPLE_PATH = "/";                         // stand-in URL when a type was never seen

function sampleUrl(entry, scope) {
  return (entry.sampleUrls && entry.sampleUrls[SCOPE_TYPE_LABEL[scope]])
      || (entry.sampleUrls && Object.values(entry.sampleUrls)[0])
      || `https://${entry.domain}${SAMPLE_PATH}`;
}

function decide(compiled, entry, scope, initiator, tabId) {
  const req = { url: sampleUrl(entry, scope), type: MATRIX_SCOPE_RESOURCE_TYPE[scope], initiator, tabId };
  return matchOutcome(compiled, req).action === MATRIX_ACTION.BLOCK ? DISPOSITION.BLOCK : DISPOSITION.ALLOW;
}

export function buildMatrixRows({ entries, overrides, level, host, tabId, compiled, compiledMode }) {
  const initiator = host ? `https://${host}` : "";
  const builtinApplies = BUILTIN_EXEMPT_LEVELS.includes(level);
  return entries.map((entry) => {
    const ov = overrides[entry.domain] || {};
    const hasOverride = Object.values(MATRIX_SCOPE).some((sc) => !!ov[sc]);
    const inBuiltin = isInDomainList(entry.domain, BUILTIN_ALL);
    const row = { domain: entry.domain, types: entry.types, count: entry.count, override: ov };

    for (const sc of Object.values(MATRIX_SCOPE)) {
      if (!entry.types.includes(SCOPE_TYPE_LABEL[sc]) && !ov[sc]) continue;   // never seen, no override
      row[sc] = { effective: decide(compiled, entry, sc, initiator, tabId), overridden: !!ov[sc] };
    }

    row.mode = (hasOverride || (inBuiltin && builtinApplies))
      ? MODE_STATE.GREY
      : decide(compiledMode, entry, MODE_SCOPE, initiator, tabId);

    row.whitelist = !inBuiltin ? WHITELIST_STATE.EMPTY
      : (hasOverride || !builtinApplies) ? WHITELIST_STATE.GREY : WHITELIST_STATE.GREEN;
    row.whitelistCategory = inBuiltin ? builtinCategoryOf(entry.domain) : "";
    row.whitelistApplies = inBuiltin && builtinApplies;
    return row;
  });
}

// Category of the most specific built-in entry covering `domain` (itself or a parent).
function builtinCategoryOf(domain) {
  let h = domain;
  for (;;) {
    if (BUILTIN_CATEGORY[h]) return BUILTIN_CATEGORY[h];
    const dot = h.indexOf(".");
    if (dot === -1) return "";
    h = h.slice(dot + 1);
  }
}
