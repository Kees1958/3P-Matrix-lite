// ── dnr-filter.mjs ────────────────────────────────────────────────────────────
// 4.4.0 — which lines of an adblock-syntax list (uBlock / ABP) 3P Matrix can use as declarativeNetRequest
// (DNR) rules. Shared by every list builder (today: build-spam-tlds.mjs), so a list never loses rules silently:
// every line gets exactly one verdict.
//
//   COMMENT       "!" / "[Adblock Plus]" headers, blank lines
//   KEEP          the builder's own accepted shape (a regex the builder passes in) — becomes data
//   DROP          not expressible as DNR at all — dropped ON PURPOSE, with the reason, and counted:
//                   cosmetic / element hiding (##, #@#, #?#, #$#, #%#), scriptlets (##+js), HTML filters (##^),
//                   and network options DNR has no equivalent for ($redirect, $replace, $csp, $popup, …),
//                   regular expressions RE2 (DNR's regex engine) cannot run (lookaround, back-references)
//   UNHANDLED     a network rule DNR COULD express, but in a shape this builder does not understand
//                   (an exception @@…, another option set, a plain regex) — the builder must FAIL on it:
//                   dropping it would silently lose real list data. Teach the builder the shape instead.
//
// Pure: no file or network access; nothing is kept between calls.
// ─────────────────────────────────────────────────────────────────────────────

// ── Settings (one place) ─────────────────────────────────────────────────────
export const DNR_VERDICT = Object.freeze({ COMMENT: "comment", KEEP: "keep", DROP: "drop", UNHANDLED: "unhandled" });

const COMMENT_PREFIXES = Object.freeze(["!", "["]);
// Cosmetic separators, longest first; "##+js(" and "##^" are refined below for a clearer reason.
const COSMETIC_RE = /#(?:@|\?|\$|%)?#|#@\$#|#@\?#|#@%#/;
const SCRIPTLET_RE = /##\+js\(|#@#\+js\(|#%#\/\/scriptlet\(/;
const HTML_FILTER_RE = /##\^/;
// Network options with no declarativeNetRequest equivalent (reason per option).
const NON_DNR_OPTIONS = Object.freeze({
  "redirect":      "$redirect: DNR redirects only to extension resources it ships, not uBlock's neutered stubs",
  "redirect-rule": "$redirect-rule: no DNR equivalent",
  "replace":       "$replace: rewrites response bodies — DNR cannot",
  "csp":           "$csp: injects a Content-Security-Policy with uBlock semantics — not expressible as DNR",
  "permissions":   "$permissions: injects a Permissions-Policy — not expressible as DNR",
  "popup":         "$popup: DNR has no notion of popups",
  "popunder":      "$popunder: DNR has no notion of popunders",
  "cname":         "$cname: needs DNS resolution of the request — DNR cannot",
  "urlskip":       "$urlskip: rewrites a link to its embedded target — DNR cannot",
  "header":        "$header: matches response headers with uBlock semantics — not expressible as DNR",
  "inline-script": "$inline-script: CSP injection — not expressible as DNR",
  "inline-font":   "$inline-font: CSP injection — not expressible as DNR",
  "genericblock":  "$genericblock: exception modifier with no DNR equivalent",
  "generichide":   "$generichide: cosmetic exception — not a request rule",
  "elemhide":      "$elemhide: cosmetic exception — not a request rule",
  "ehide":         "$ehide: cosmetic exception — not a request rule",
  "specifichide":  "$specifichide: cosmetic exception — not a request rule",
  "shide":         "$shide: cosmetic exception — not a request rule",
  "ghide":         "$ghide: cosmetic exception — not a request rule",
});
const RE2_UNSUPPORTED_RE = /\(\?<?[=!]|\\[1-9]/;     // lookahead/lookbehind, back-references
const REGEX_RULE_RE = /^(?:@@)?\/.+\/(?:\$.*)?$/;
const OPTIONS_RE = /\$([^/]*)$/;                       // the $option list after the pattern

function optionNames(line) {
  const m = OPTIONS_RE.exec(line);
  if (!m) return [];
  return m[1].split(",").map(o => o.trim().replace(/^~/, "").split("=")[0].toLowerCase()).filter(Boolean);
}

/**
 * @param {string} rawLine  one line of the list
 * @param {RegExp} keepRe   the builder's accepted shape (anchored)
 * @returns {{ verdict: string, reason: string|null }}
 */
export function classifyFilterLine(rawLine, keepRe) {
  const line = (rawLine || "").trim();
  if (!line || COMMENT_PREFIXES.some(p => line.startsWith(p))) return { verdict: DNR_VERDICT.COMMENT, reason: null };
  if (SCRIPTLET_RE.test(line))   return { verdict: DNR_VERDICT.DROP, reason: "scriptlet injection (##+js) — runs code in the page, not a request rule" };
  if (HTML_FILTER_RE.test(line)) return { verdict: DNR_VERDICT.DROP, reason: "HTML filter (##^) — edits the page source, not a request rule" };
  if (COSMETIC_RE.test(line))    return { verdict: DNR_VERDICT.DROP, reason: "cosmetic / element hiding — hides page content, not a request rule" };
  if (REGEX_RULE_RE.test(line) && RE2_UNSUPPORTED_RE.test(line)) {
    return { verdict: DNR_VERDICT.DROP, reason: "regular expression with lookaround or back-reference — DNR's RE2 engine cannot run it" };
  }
  for (const name of optionNames(line)) {
    if (NON_DNR_OPTIONS[name]) return { verdict: DNR_VERDICT.DROP, reason: NON_DNR_OPTIONS[name] };
  }
  if (keepRe.test(line)) return { verdict: DNR_VERDICT.KEEP, reason: null };
  return { verdict: DNR_VERDICT.UNHANDLED, reason: "DNR could express this rule, but the builder does not understand its shape" };
}

/**
 * Classify a whole list. Returns the kept lines plus counted drops/unhandled with reasons.
 * @returns {{ kept: string[], dropped: {line:string, reason:string}[], unhandled: {line:string, reason:string}[], read: number }}
 */
export function filterList(text, keepRe) {
  const out = { kept: [], dropped: [], unhandled: [], read: 0 };
  for (const raw of String(text).split(/\r?\n/)) {
    const { verdict, reason } = classifyFilterLine(raw, keepRe);
    if (verdict === DNR_VERDICT.COMMENT) continue;
    out.read++;
    const line = raw.trim();
    if (verdict === DNR_VERDICT.KEEP) out.kept.push(line);
    else if (verdict === DNR_VERDICT.DROP) out.dropped.push({ line, reason });
    else out.unhandled.push({ line, reason });
  }
  return out;
}
