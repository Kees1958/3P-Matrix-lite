#!/usr/bin/env node
// ── tools/test-small-signals.mjs ─────────────────────────────────────────────
// 5.0.4 (DownloadSentinel 3.5.6) — small signals (weaker than CombinationScoring's STACK_MIN_SIGNAL) add up only
// when the heuristics are the only indicator AND the source is dubious (user decision 2026-11-09). The shared rule is
// unit-tested in DownloadSentinel (tests/SmallSignalStacking.test.js); this covers 3P Matrix's own consumers:
//   1. the site check (core/site-scorer.js combine()) — no VirusTotal on a site visit, so always heuristics only;
//   2. the download check's active-threat floor (core/download-guard.js) — must floor BOTH host verdicts;
//   3. the real report end to end: a hidden .bin from a drive.google.com link, VirusTotal unknown, default FP level.
// No score is typed into an assertion: expectations come from the extension's own constants.
//
// Usage:  node test-small-signals.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const DRIVE_LINK = "https://drive.google.com/uc?export=download&id=1N6hYIxV2EXw5gdNAOzoymk4NA2IzPQGi";   // the reported link
const DRIVE_FILE = "https://drive.usercontent.google.com/download?id=1N6hYIxV2EXw5gdNAOzoymk4NA2IzPQGi&export=download";
const DRIVE_NAME = "file.bin";                       // the name Drive revealed after the redirect
const DRIVE_MIME = "application/octet-stream";
const DRIVE_BYTES = 4 * 1024 * 1024;                 // a typical small payload (size is not what this tests)
const ACTIVE_THREAT_URL = "https://raw.githubusercontent.com/user/repo/main/payload.zip";
const DEFAULT_FP_LEVEL = "MEDIUM";
const SMALL_SOURCE = "SketchyUrl";                   // a small route signal
const NOT_DUBIOUS_SOURCE = "LookalikeDomain";        // strong, but not a dubious-SOURCE list
const VT_UNKNOWN = true;

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-small-signals: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const load = (rel) => import(pathToFileURL(resolve(ext, rel)).href);

// Offline: DNS threat-intel and RDAP lookups fail → "unknown", as with no network (google.com is old anyway).
globalThis.fetch = async () => { throw new Error("offline test"); };
globalThis.chrome = { storage: { local: { get: async () => ({}), set: async () => {} }, session: { get: async () => ({}), set: async () => {} } },
                      runtime: { getManifest: () => ({ version: "0" }) } };

let CS, SE, BP, FA, WP, SS, DG, C;
try {
  ({ CombinationScoring: CS } = await load("lib/downloadsentinel/protection/CombinationScoring.js"));
  ({ ScoringEngineV2: SE } = await load("lib/downloadsentinel/protection/ScoringEngineV2.js"));
  ({ BrowserProtection: BP } = await load("lib/downloadsentinel/protection/BrowserProtection.js"));
  ({ FilenameAnalysis: FA } = await load("lib/downloadsentinel/util/FilenameAnalysis.js"));
  ({ WarnPolicy: WP } = await load("lib/downloadsentinel/protection/WarnPolicy.js"));
  SS = await load("core/site-scorer.js");
  DG = await load("core/download-guard.js");
  C = await load("data/constants.js");
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }
if (typeof CS.smallSignalsStack !== "function" || typeof SE.hostVerdict !== "function") didNotRun("the shared library has no small-signal rule (DS < 3.5.6)");

let failed = 0;
function ok(name, cond, detail = "") { console.log(`${cond ? "      PASS" : "      FAIL"} ${name}${cond ? "" : "  " + JSON.stringify(detail)}`); if (!cond) failed++; }

const SMALL = CS.CONFIG.STACK_MIN_SIGNAL + 1;
const STRONG = C.SCORE.SUSPECT_AT;                                    // a site signal right at the suspect line
const entry = (source, score) => ({ source, score, label: source });

// 1 — site check: a dubious host + a small signal adds up; a non-dubious one does not (no VirusTotal on a visit).
{
  const dubious = SS.combine([entry(CS.CONFIG.DUBIOUS_SOURCES[0], STRONG), entry(SMALL_SOURCE, SMALL)]);
  const plain = SS.combine([entry(NOT_DUBIOUS_SOURCE, STRONG), entry(SMALL_SOURCE, SMALL)]);
  ok("site check: dubious source + small signal adds up", dubious.score < STRONG, dubious);
  ok("site check: not a dubious source → unchanged", plain.score === STRONG, plain);
}

// 2 — download floor: both verdicts are floored.
{
  const r = SE.evaluateHostReputation({ dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
                                        mimeResult: null, sizeResult: null, riskyHosting: null, url: ACTIVE_THREAT_URL, fileType: "archive" });
  const f = DG.applyActiveThreatFloor(r, [ACTIVE_THREAT_URL]);
  ok("download floor: VirusTotal-known verdict floored", SE.hostVerdict(f, false).score <= C.SCORE.ACTIVE_THREAT_HOST, SE.hostVerdict(f, false));
  ok("download floor: heuristics-only verdict floored", SE.hostVerdict(f, VT_UNKNOWN).score <= C.SCORE.ACTIVE_THREAT_HOST, SE.hostVerdict(f, VT_UNKNOWN));
}

// 3 — the reported case, through the real host check (name revealed after the redirect, VirusTotal unknown).
{
  const c = FA.classifyDownload(DRIVE_FILE, DRIVE_LINK, DRIVE_NAME, DRIVE_MIME);
  const suggested = FA.getRawExt(FA.extractFilenameFromUrl(DRIVE_LINK));
  const obfuscation = FA.getObfuscationSignal(suggested, c.ext);
  let r = await BP.checkHostReputation(DRIVE_FILE, c.fileType, c.ext, DRIVE_MIME, DRIVE_BYTES, DRIVE_LINK, c.isScript, obfuscation,
                                        null, false, DRIVE_NAME, true, null, null, null);
  r = DG.applyActiveThreatFloor(r, [DRIVE_FILE, DRIVE_LINK]);
  const known = SE.hostVerdict(r, false), unknown = SE.hostVerdict(r, VT_UNKNOWN);
  const decision = WP.downloadDecision({ combinedScore: unknown.score, fpLevel: DEFAULT_FP_LEVEL, entries: unknown.breakdown });
  ok("Drive .bin: heuristics only scores worse than VirusTotal-known", unknown.score < known.score, { known: known.score, unknown: unknown.score });
  ok("Drive .bin: the warning window opens at the default FP level", decision.warn, { score: unknown.score, decision });
}

console.log(failed ? `test-small-signals: ${failed} FAILED` : "test-small-signals: all pass");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
