#!/usr/bin/env node
// ── tools/test-dns-block-styles.mjs ──────────────────────────────────────────────
// Unit test (4.3.7) for the SITE check's own DNS code (core/online-checks.js — 3P Matrix keeps its own DoH
// implementation next to DownloadSentinel's, 4.3.4 item 21), for the first-install DNS pair (4.5.8: Control D +
// DNS4EU in every region) and for the schema-5 migration of an untouched old default (data/state-storage.js —
// old default per region from DownloadSentinel DnsDefaults).
// Fixtures are the replies observed live on 2026-10-24 (via digwebinterface.com):
//   DNS4EU 86.54.11.1        malware.wicar.org → A 51.15.69.11 (block page)
//   CleanBrowsing 185.228.168.9  malware.wicar.org → no answer + SOA cleanbrowsing.rpz.noc.org (policy zone)
//   both                     thisdoesnotexist-12345.com → NXDOMAIN + "com." SOA a.gtld-servers.net
// Provider ids, block-page IPs and the RPZ suffix are read from the extension's constants — never typed here.
//
// Usage:  node test-dns-block-styles.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const WIRE = Object.freeze({                        // RFC 1035 values used by the fixture builder
  TYPE_A: 1, TYPE_SOA: 6, CLASS_IN: 1, RCODE_NOERROR: 0, RCODE_NXDOMAIN: 3,
  FLAGS_HI: 0x81,                                   // QR + RD
  TTL: [0, 0, 0x0e, 0x10],                          // 3600 s
  SOA_TIMERS: new Array(20).fill(0),                // serial/refresh/retry/expire/minimum — values irrelevant
  BYTE_MASK: 0xff, BYTE_BITS: 8
});
const OBSERVED = Object.freeze({
  BLOCKED_HOST:   "malware.wicar.org",
  MISSING_HOST:   "thisdoesnotexist-12345.com",
  CLEAN_HOST:     "example.com",
  CLEAN_IP:       "104.20.23.154",
  RPZ_MNAME:      "cleanbrowsing.rpz.noc.org",
  RPZ_RNAME:      "accesspolicy.rpz.noc.org",
  REGISTRY_OWNER: "com",
  REGISTRY_MNAME: "a.gtld-servers.net",
  REGISTRY_RNAME: "nstld.verisign-grs.com",
  LOOKALIKE_MNAME: "evilrpz.noc.org"
});
const TZ = Object.freeze({ FRANCE: "Europe/Paris", REUNION: "Indian/Reunion", NETHERLANDS: "Europe/Amsterdam", MONACO: "Europe/Monaco" });

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-dns-block-styles: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const load = (rel) => import(pathToFileURL(resolve(ext, rel)).href);

let C, evaluateSite, clearScoreCache, CHECK_STATUS, defaultState, normalizeState, DnsDefaults;
try {
  C = await load("data/constants.js");
  ({ evaluateSite, clearScoreCache, CHECK_STATUS } = await load("core/online-checks.js"));
  ({ defaultState, normalizeState } = await load("data/state-storage.js"));
  ({ DnsDefaults } = await load("lib/downloadsentinel/util/DnsDefaults.js"));
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }

// ── Fixture builder (independent of the extension's own codec) ───────────────
const u16 = (n) => [(n >> WIRE.BYTE_BITS) & WIRE.BYTE_MASK, n & WIRE.BYTE_MASK];
function labels(name) {
  const out = [];
  for (const l of name.split(".").filter(Boolean)) { const b = new TextEncoder().encode(l); out.push(b.length, ...b); }
  out.push(0);
  return out;
}
function reply({ qname, rcode = WIRE.RCODE_NOERROR, a = [], soa = [], claimedAuthority = null }) {
  const nsCount = claimedAuthority ?? soa.length;
  const bytes = [0, 0, WIRE.FLAGS_HI, rcode, ...u16(1), ...u16(a.length), ...u16(nsCount), ...u16(0),
                 ...labels(qname), ...u16(WIRE.TYPE_A), ...u16(WIRE.CLASS_IN)];
  for (const ip of a) {
    bytes.push(...labels(qname), ...u16(WIRE.TYPE_A), ...u16(WIRE.CLASS_IN), ...WIRE.TTL, ...u16(4), ...ip.split(".").map(Number));
  }
  for (const s of soa) {
    const rdata = [...labels(s.mname), ...labels(s.rname), ...WIRE.SOA_TIMERS];
    bytes.push(...labels(s.owner), ...u16(WIRE.TYPE_SOA), ...u16(WIRE.CLASS_IN), ...WIRE.TTL, ...u16(rdata.length), ...rdata);
  }
  return new Uint8Array(bytes).buffer;
}

// ── fetch mock: RDAP always fails (not under test); DoH returns the case's fixture ──
let currentReply = null;
let dohCalls = [];
globalThis.fetch = async (url) => {
  if (String(url).startsWith(C.RDAP_URL)) return { ok: false, status: 503 };
  dohCalls.push(String(url));
  return { ok: true, status: 200, arrayBuffer: async () => currentReply };
};

async function dnsStatus(providerId, host, fixture) {
  clearScoreCache();
  currentReply = fixture;
  dohCalls = [];
  const local = { site: host, host, score: 0, entries: [], signals: [] };
  const r = await evaluateSite(local, { first: providerId, second: C.DNS_NONE });
  return r.checks.dns[0];
}

// ── Cases ────────────────────────────────────────────────────────────────────
let failed = 0;
function ok(name, cond, detail) {
  if (cond) console.log(`  ok  ${name}`);
  else { failed++; console.log(`  FAIL ${name}${detail === undefined ? "" : ` — ${JSON.stringify(detail)}`}`); }
}

const DNS4EU = C.DNS_PROVIDER.DNS4EU, CB = C.DNS_PROVIDER.CLEANBROWSING, CF = C.DNS_PROVIDER.CLOUDFLARE;
const rpzSoa = { owner: OBSERVED.BLOCKED_HOST, mname: OBSERVED.RPZ_MNAME, rname: OBSERVED.RPZ_RNAME };
const registrySoa = { owner: OBSERVED.REGISTRY_OWNER, mname: OBSERVED.REGISTRY_MNAME, rname: OBSERVED.REGISTRY_RNAME };
const missing = reply({ qname: OBSERVED.MISSING_HOST, rcode: WIRE.RCODE_NXDOMAIN, soa: [registrySoa] });
const clean = reply({ qname: OBSERVED.CLEAN_HOST, a: [OBSERVED.CLEAN_IP] });

console.log("DNS4EU (BLOCKPAGE_IP)");
let r = await dnsStatus(DNS4EU.id, OBSERVED.BLOCKED_HOST, reply({ qname: OBSERVED.BLOCKED_HOST, a: [DNS4EU.blockPageIps[0]] }));
ok("block-page IP → blocked", r.status === CHECK_STATUS.BLOCKED, r);
ok("queries DNS4EU's DoH address", dohCalls[0]?.startsWith(`${DNS4EU.url}?dns=`), dohCalls);
r = await dnsStatus(DNS4EU.id, OBSERVED.MISSING_HOST, missing);
ok("NXDOMAIN + registry SOA → unavailable (domain does not exist), never blocked", r.status === CHECK_STATUS.UNAVAILABLE, r);
r = await dnsStatus(DNS4EU.id, OBSERVED.CLEAN_HOST, clean);
ok("normal address → allowed", r.status === CHECK_STATUS.ALLOWED, r);
r = await dnsStatus(CF.id, OBSERVED.CLEAN_HOST, reply({ qname: OBSERVED.CLEAN_HOST, a: [DNS4EU.blockPageIps[0]] }));
ok("Cloudflare (ZERO_IP) does not treat DNS4EU's block-page IP as a block", r.status === CHECK_STATUS.ALLOWED, r);

console.log("CleanBrowsing (RPZ_SOA)");
r = await dnsStatus(CB.id, OBSERVED.BLOCKED_HOST, reply({ qname: OBSERVED.BLOCKED_HOST, rcode: WIRE.RCODE_NXDOMAIN, soa: [rpzSoa] }));
ok("no answer + policy-zone SOA → blocked", r.status === CHECK_STATUS.BLOCKED, r);
ok("queries CleanBrowsing's Security Filter DoH address", dohCalls[0]?.startsWith(`${CB.url}?dns=`), dohCalls);
r = await dnsStatus(CB.id, OBSERVED.BLOCKED_HOST, reply({ qname: OBSERVED.BLOCKED_HOST, rcode: WIRE.RCODE_NOERROR, soa: [rpzSoa] }));
ok("same block with NOERROR/NODATA → still blocked (the SOA is the signal)", r.status === CHECK_STATUS.BLOCKED, r);
r = await dnsStatus(CB.id, OBSERVED.MISSING_HOST, missing);
ok("NXDOMAIN + registry SOA → unavailable (domain does not exist), never blocked",
   r.status === CHECK_STATUS.UNAVAILABLE && /does not exist/.test(r.reason), r);
r = await dnsStatus(CB.id, OBSERVED.CLEAN_HOST, reply({ qname: OBSERVED.CLEAN_HOST, rcode: WIRE.RCODE_NXDOMAIN,
  soa: [{ owner: OBSERVED.CLEAN_HOST, mname: OBSERVED.LOOKALIKE_MNAME, rname: OBSERVED.RPZ_RNAME }] }));
ok("look-alike MNAME without label boundary → not blocked", r.status !== CHECK_STATUS.BLOCKED, r);
r = await dnsStatus(CB.id, OBSERVED.CLEAN_HOST, clean);
ok("normal address → allowed", r.status === CHECK_STATUS.ALLOWED, r);
r = await dnsStatus(CB.id, OBSERVED.CLEAN_HOST, reply({ qname: OBSERVED.CLEAN_HOST, a: [OBSERVED.CLEAN_IP], claimedAuthority: 1 }));
ok("truncated authority section → answer still used (allowed), never blocked", r.status === CHECK_STATUS.ALLOWED, r);
r = await dnsStatus(C.DNS_PROVIDER.QUAD9.id, OBSERVED.BLOCKED_HOST, reply({ qname: OBSERVED.BLOCKED_HOST, rcode: WIRE.RCODE_NXDOMAIN, soa: [rpzSoa] }));
ok("Quad9 (NXDOMAIN_NO_AUTHORITY) ignores an RPZ SOA (authority present → not blocked)", r.status !== CHECK_STATUS.BLOCKED, r);

console.log("First-install DNS pair (4.5.8: one pair everywhere) + schema-5 migration of an untouched old default");
const realDTF = Intl.DateTimeFormat;
function inZone(tz, fn) {                                           // guard: fake Intl + fresh cache, always released
  Intl.DateTimeFormat = tz === null ? function () { throw new Error("no Intl"); }
                                    : function () { return { resolvedOptions: () => ({ timeZone: tz }) }; };
  try { DnsDefaults.reset(); return fn(); }
  finally { Intl.DateTimeFormat = realDTF; DnsDefaults.reset(); }
}
const P = C.DNS_PROVIDER, NEW = { first: C.DEFAULT_DNS_FIRST, second: C.DEFAULT_DNS_SECOND };
const frRule = (await load("lib/downloadsentinel/util/AppConstants.js")).APP.DNS_REGION_DEFAULTS.find((x) => x.region === "FR");
const same = (a, b) => a.first === b.first && a.second === b.second;
const OLD_SCHEMA = C.STATE_SCHEMA_VERSION - 1;
const migrated = (tz, dns, schema = OLD_SCHEMA) => inZone(tz, () => normalizeState({ schema, dns }).dns);

ok("default pair is Control D first, DNS4EU second", NEW.first === P.CONTROLD.id && NEW.second === P.DNS4EU.id, NEW);
for (const tz of [TZ.FRANCE, TZ.REUNION, TZ.NETHERLANDS, TZ.MONACO, null]) {
  const d = inZone(tz, () => defaultState().dns);
  ok(`first install, ${tz ?? "Intl failing"} → the default pair (no region rule)`, same(d, NEW), d);
}
let d = migrated(TZ.NETHERLANDS, { ...C.LEGACY_DNS_DEFAULT });
ok("old global default (Quad9 + Cloudflare), never changed → new pair", same(d, NEW), d);
d = migrated(TZ.FRANCE, { first: frRule.first, second: frRule.second });
ok("France: old FR default (Control D + Cloudflare), never changed → new pair", same(d, NEW), d);
d = migrated(TZ.REUNION, { first: frRule.first, second: frRule.second });
ok("French overseas (Réunion): old FR default → new pair", same(d, NEW), d);
d = migrated(TZ.NETHERLANDS, { first: frRule.first, second: frRule.second });
ok("outside France, Control D + Cloudflare is a user's own choice → kept", same(d, frRule), d);
d = migrated(TZ.FRANCE, { ...C.LEGACY_DNS_DEFAULT });
ok("France, Quad9 + Cloudflare is a user's own choice (FR default was different) → kept", same(d, C.LEGACY_DNS_DEFAULT), d);
const own = { first: P.QUAD9.id, second: C.DNS_NONE };
d = migrated(TZ.NETHERLANDS, own);
ok("a changed pair (Quad9, second off) → kept", same(d, own), d);
d = migrated(TZ.NETHERLANDS, { ...C.LEGACY_DNS_DEFAULT }, C.STATE_SCHEMA_VERSION);
ok("current-schema data is not migrated again (Quad9 + Cloudflare chosen after 4.5.8 → kept)", same(d, C.LEGACY_DNS_DEFAULT), d);
d = migrated(TZ.NETHERLANDS, undefined);
ok("old data without a DNS pair → the default pair", same(d, NEW), d);

console.log(failed ? `test-dns-block-styles: ${failed} case(s) FAILED` : "test-dns-block-styles: all cases pass");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
