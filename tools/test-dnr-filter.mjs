#!/usr/bin/env node
// ── test-dnr-filter.mjs ──────────────────────────────────────────────────────
// Unit test (4.4.0) for dnr-filter.mjs: every adblock-list line gets exactly one verdict — kept, dropped on
// purpose because declarativeNetRequest cannot express it (with a reason), or "not understood" (a rule DNR
// could express in a shape the builder does not know — the builder must fail on those, never drop them).
// Also checks build-spam-tlds.mjs's accepted shape against the real shipped source list.
//
// Usage:  node test-dnr-filter.mjs [--extension ../3P-Matrix]   (--extension accepted for suite symmetry)
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { classifyFilterLine, filterList, DNR_VERDICT } from "./dnr-filter.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const HERE = dirname(fileURLToPath(import.meta.url));
const SPAM_TLD_SOURCE = join(HERE, "spam-tlds-ublock.txt");
// build-spam-tlds.mjs's accepted shape, repeated here ON PURPOSE as the contract under test.
const KEEP_RE = /^\|\|([^\^]+)\^\$doc(?:,domain=(.+))?$/;

const CASES = Object.freeze([
  ["! Title: comment",                              DNR_VERDICT.COMMENT],
  ["[Adblock Plus]",                                DNR_VERDICT.COMMENT],
  ["",                                              DNR_VERDICT.COMMENT],
  ["||actor^$doc",                                  DNR_VERDICT.KEEP],
  ["||africa^$doc,domain=~nation.africa",           DNR_VERDICT.KEEP],
  ["example.com##.ad-banner",                       DNR_VERDICT.DROP],
  ["example.com#@#.ad-banner",                      DNR_VERDICT.DROP],
  ["example.com#?#div:has(> .ad)",                  DNR_VERDICT.DROP],
  ["example.com##+js(set-constant, x, true)",       DNR_VERDICT.DROP],
  ["example.com##^script:has-text(ad)",             DNR_VERDICT.DROP],
  ["||ads.example^$redirect=noopjs",                DNR_VERDICT.DROP],
  ["||example.com^$csp=script-src 'none'",          DNR_VERDICT.DROP],
  ["||example.com^$popup",                          DNR_VERDICT.DROP],
  ["||example.com^$removeparam=utm_source",         DNR_VERDICT.UNHANDLED],   // DNR can (queryTransform) — builder can't
  ["/^https?:\\/\\/(?!good)[a-z]+\\.top\\//$doc",   DNR_VERDICT.DROP],        // lookahead: RE2 cannot
  ["/^https?:\\/\\/[a-z]+\\.top\\//$doc",           DNR_VERDICT.UNHANDLED],   // plain regex: DNR can, builder can't
  ["@@||good.top^$doc",                             DNR_VERDICT.UNHANDLED],   // exception: DNR can (allow), builder can't
  ["||actor^",                                      DNR_VERDICT.UNHANDLED],   // other option set
]);

let failed = 0;
function ok(name, cond, detail) {
  if (cond) console.log(`  PASS ${name}`);
  else { failed++; console.log(`  FAIL ${name}  ${detail ?? ""}`); }
}

for (const [line, expected] of CASES) {
  const { verdict, reason } = classifyFilterLine(line, KEEP_RE);
  ok(`"${line || "(blank)"}" → ${expected}`, verdict === expected, `got ${verdict}`);
  if (verdict === DNR_VERDICT.DROP || verdict === DNR_VERDICT.UNHANDLED) ok(`  … with a reason`, typeof reason === "string" && reason.length > 0);
}

const mixed = filterList(CASES.map(([l]) => l).join("\n"), KEEP_RE);
const nonComment = CASES.filter(([, v]) => v !== DNR_VERDICT.COMMENT).length;
ok("filterList: every non-comment line counted exactly once",
   mixed.read === nonComment && mixed.kept.length + mixed.dropped.length + mixed.unhandled.length === nonComment,
   JSON.stringify({ read: mixed.read, kept: mixed.kept.length, dropped: mixed.dropped.length, unhandled: mixed.unhandled.length }));

if (!existsSync(SPAM_TLD_SOURCE)) {
  console.log(`test-dnr-filter: DID NOT RUN — ${SPAM_TLD_SOURCE} missing`);
  process.exit(EXIT.DID_NOT_RUN);
}
const real = filterList(readFileSync(SPAM_TLD_SOURCE, "utf8"), KEEP_RE);
ok(`shipped spam-TLD source: nothing "not understood" (${real.read} rules, ${real.dropped.length} dropped)`,
   real.unhandled.length === 0, real.unhandled.slice(0, 3).map(u => u.line).join(" | "));

console.log(failed ? `test-dnr-filter: ${failed} FAILED` : "test-dnr-filter: all passed");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
