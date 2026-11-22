#!/usr/bin/env node
// ── tools/test-large-binary.mjs ──────────────────────────────────────────────────
// Unit test (4.5.6, user request after a real case: an 80 MB extensionless blob from cdn.discordapp.com was
// only "Probably Inconclusive") for the large-extensionless-binary rule in the shared DownloadSentinel
// scoring (ScoringEngineV2 Check 26): a file with no extension and a generic binary type, at least
// SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_MIN_BYTES large, from a file-sharing host (RiskyHostingSites)
// scores LARGE_EXTENSIONLESS_BINARY_SCORE and reaches "Probably Suspicious" (4.5.8: + huge tier at VirusTotal's limit); below the size, with the size
// still unknown, or from another host, nothing changes. Every expected value comes from SCORING_CONFIG.
//
// Usage:  node test-large-binary.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const SOURCE = "ExtensionlessBinary";
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-large-binary: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
let ScoringEngineV2, SCORING_CONFIG, RiskyHostingSites;
try {
  ({ ScoringEngineV2, SCORING_CONFIG } = await import(pathToFileURL(resolve(ext, "lib/downloadsentinel/protection/ScoringEngineV2.js")).href));
  ({ RiskyHostingSites } = await import(pathToFileURL(resolve(ext, "lib/downloadsentinel/util/RiskyHostingSites.js")).href));
} catch (e) { didNotRun(`cannot import the scoring modules: ${e.message}`); }
if (SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_MIN_BYTES === undefined) didNotRun("SCORING_CONFIG has no LARGE_EXTENSIONLESS_BINARY_MIN_BYTES");

let failed = 0;
function ok(name, cond, info) {
  if (!cond) failed++;
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : "  " + JSON.stringify(info)}`);
}

const MIN = SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_MIN_BYTES;
const FILE_HOST = "cdn.discordapp.com";                      // the real case — must be on the shipped risky-host list
const risky = RiskyHostingSites.lookup(FILE_HOST);
ok(`${FILE_HOST} is a file-sharing host in the shipped list`, !!risky, risky);
const base = { rdap: { status: "UNKNOWN", score: 0 }, domainHit: null, tldHit: null, sketchyUrl: { score: 0, signals: [] },
               mimeResult: { neutral: true, score: 0 }, sizeResult: { exceeds: false, score: 0 },
               url: `https://${FILE_HOST}/attachments/1/2/d717ab737d`, fileType: "unknown-binary", isUnknownBinary: true };
const run = (extra) => ScoringEngineV2.evaluateHostReputation({ ...base, ...extra });
const entry = (r) => r.breakdown.find((b) => b.source === SOURCE) || {};
const C = ScoringEngineV2.Classification;

let r = run({ riskyHosting: risky, totalBytes: MIN });
ok("at the size limit, from a file-sharing host → heavier signal + Probably Suspicious",
   entry(r).score === SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_SCORE && r.classification === C.PROBABLY_SUSPICIOUS, r);
r = run({ riskyHosting: risky, totalBytes: MIN - 1 });
ok("just below the size limit → the normal signal", entry(r).score === SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE, r);
r = run({ riskyHosting: risky, totalBytes: 0 });
ok("size not known yet → the normal signal (re-scored at completion)", entry(r).score === SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE, r);
r = run({ riskyHosting: null, totalBytes: MIN });
ok("large, but not from a file-sharing host → the normal signal", entry(r).score === SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE, r);
r = run({ riskyHosting: risky, totalBytes: MIN, isUnknownBinary: false });
ok("a file with an extension is never touched", !r.breakdown.some((b) => b.source === SOURCE), r);


// 4.5.8 — huge tier (≥ HUGE_EXTENSIONLESS_BINARY_MIN_BYTES = VirusTotal's limit): heavier than the large tier, and it
// REPLACES Check 7 (SizeCheck) for that file — one fact, one signal. Other files keep Check 7 unchanged.
const { MimeCheck } = await import(pathToFileURL(resolve(ext, "lib/downloadsentinel/protection/MimeCheck.js")).href);
const HUGE = SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_MIN_BYTES;
const SIZE_SOURCE = "SizeCheck";
const runSized = (bytes, extra = {}) => run({ riskyHosting: risky, totalBytes: bytes, sizeResult: MimeCheck.checkSize(bytes), ...extra });
ok("huge tier starts at VirusTotal's limit (one value)", HUGE === MimeCheck.VT_MAX_BYTES && HUGE === SCORING_CONFIG.VT_MAX_BYTES, { HUGE });
ok("huge tier is heavier than the large tier", SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_SCORE < SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_SCORE);
const big = SCORING_CONFIG.BYTES_PER_MB;
r = runSized(HUGE);
ok("at the huge limit → huge signal", entry(r).score === SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_SCORE, r);
r = runSized(HUGE + big);
ok("above the huge limit → huge signal, no separate VirusTotal-size signal",
   entry(r).score === SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_SCORE && !r.breakdown.some((b) => b.source === SIZE_SOURCE), r);
const largeScore = runSized(MIN).score;
ok("huge file scores worse than a large one, still Probably Suspicious",
   r.score < largeScore && r.classification === C.PROBABLY_SUSPICIOUS, { huge: r.score, large: largeScore, cls: r.classification });
r = runSized(HUGE - 1);
ok("just below the huge limit → large signal", entry(r).score === SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_SCORE, r);
r = runSized(HUGE + big, { riskyHosting: null });
ok("huge but not from a file-sharing host → normal signal, VirusTotal-size signal kept",
   entry(r).score === SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE && r.breakdown.some((b) => b.source === SIZE_SOURCE), r);
r = runSized(HUGE + big, { isUnknownBinary: false });
ok("a file with an extension: VirusTotal-size signal kept, no Check 26", r.breakdown.some((b) => b.source === SIZE_SOURCE) && !r.breakdown.some((b) => b.source === SOURCE), r);

console.log(failed ? `test-large-binary: ${failed} FAILED` : "test-large-binary: ALL PASS");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
