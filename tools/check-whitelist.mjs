#!/usr/bin/env node
// ── tools/check-whitelist.mjs ────────────────────────────────────────────────────
// Release gate for the built-in whitelist (data/builtin-domains.js) — 4.5.6, after a Discord attachment
// was downloaded unchecked: Discord had been filed as a "meeting embed" while DownloadSentinel's own lists
// mark its attachment hosts as risky. Fails when:
//   1. an entry is malformed — not a lower-case host, unknown type, no category, or no reason
//   2. a host is listed twice
//   3. an entry covers, or is covered by, a host on a download risk list: DownloadSentinel RiskyHostingSites,
//      SuspiciousDomains and HostList, and data/active-threat-hosts.js (a trusted host must never hide one)
//   4. a host removed in a review (BUILTIN_REMOVED) is listed again
//   5. the derived exports disagree with the entries (BUILTIN_ALL / BUILTIN_CATEGORY / BUILTIN_PAYMENT)
// Whether a category DESCRIBES its host cannot be checked mechanically: every entry carries a one-line
// reason for review instead (rule 1 makes sure it is there).
//
// Usage:  node check-whitelist.mjs --extension ../3P-Matrix
// Exit:   0 = clean · 1 = a rule is broken · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { readListData } from "./list-modules.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const HOST_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const TYPES = new Set(["both", "script", "frame"]);
const RISK_LISTS = Object.freeze({
  RiskyHostingSites: (d) => d.map((e) => e.host),
  SuspiciousDomains: (d) => Object.keys(d),
  HostList: (d) => Object.keys(d)
});

function didNotRun(msg) { console.error(`check-whitelist: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
const under = (h, d) => h === d || h.endsWith("." + d);

const ext = arg("extension") ? resolve(arg("extension")) : null;
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");

let B, AT;
const risk = new Map();                              // risky host → which list
try {
  B = await import(pathToFileURL(join(ext, "data/builtin-domains.js")).href);
  AT = await import(pathToFileURL(join(ext, "data/active-threat-hosts.js")).href);
  for (const [name, hostsOf] of Object.entries(RISK_LISTS)) for (const h of hostsOf(await readListData(ext, name))) risk.set(h, name);
  for (const { host } of AT.ACTIVE_THREAT_HOSTS) risk.set(host, "active-threat-hosts");
} catch (e) { didNotRun(`cannot read the whitelist or the risk lists: ${e.message}`); }
if (!B.BUILTIN_ENTRIES || !B.BUILTIN_ENTRIES.length) didNotRun("data/builtin-domains.js exports no BUILTIN_ENTRIES");

const problems = [];
const labels = new Set(Object.values(B.BUILTIN_GROUP).map((g) => g.label));
const seen = new Set();
for (const e of B.BUILTIN_ENTRIES) {
  if (!HOST_RE.test(e.host)) problems.push(`${e.host}: not a lower-case host name`);
  if (!TYPES.has(e.type)) problems.push(`${e.host}: unknown type "${e.type}"`);
  if (!labels.has(e.category)) problems.push(`${e.host}: unknown category "${e.category}"`);
  if (!e.reason || !e.reason.trim()) problems.push(`${e.host}: no reason`);
  if (seen.has(e.host)) problems.push(`${e.host}: listed twice`);
  seen.add(e.host);
  for (const [r, list] of risk) {
    if (under(r, e.host) || under(e.host, r)) problems.push(`${e.host} (${e.category}) overlaps ${r} on the download risk list ${list}`);
  }
  if (B.BUILTIN_REMOVED[e.host]) problems.push(`${e.host}: was removed or rejected (${B.BUILTIN_REMOVED[e.host]}) — listing it needs a new decision`);
}
const hosts = B.BUILTIN_ENTRIES.map((e) => e.host);
if (JSON.stringify([...B.BUILTIN_ALL].sort()) !== JSON.stringify([...hosts].sort())) problems.push("BUILTIN_ALL differs from the entries");
if (Object.keys(B.BUILTIN_CATEGORY).length !== hosts.length) problems.push("BUILTIN_CATEGORY differs from the entries");
if (!B.BUILTIN_PAYMENT.every((h) => B.BUILTIN_CATEGORY[h] === B.BUILTIN_GROUP.PAYMENT.label)) problems.push("BUILTIN_PAYMENT holds a non-payment host");

if (problems.length) {
  console.error(`check-whitelist: FAIL — ${problems.length} problem(s):`);
  for (const p of problems) console.error("  " + p);
  process.exit(EXIT.FOUND);
}
console.log(`check-whitelist: PASS — ${hosts.length} entries in ${labels.size} categories, none on a download risk list (${risk.size} risky hosts checked), ${Object.keys(B.BUILTIN_REMOVED).length} removed hosts stay out`);
process.exit(EXIT.OK);
