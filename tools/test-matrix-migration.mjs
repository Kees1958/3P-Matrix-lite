#!/usr/bin/env node
// ── tools/test-matrix-migration.mjs ──────────────────────────────────────────────
// Unit test for the state schema migrations and the Show Matrix normalization (data/state-storage.js):
// global-only storage and the schema steps still converted. 4.5.4: the schema-2 conversion (per-site →
// global, { code, all } → scopes) and the v1 backup format were removed (removal scheduled for 4.5) — the cases
// below now prove such old data is DROPPED cleanly (no crash, nothing half-converted).
// Every expected value comes from the extension's own constants (single source of truth) —
// no priority, cap, key or action is typed here.
//
// Usage:  node test-matrix-migration.mjs --extension ../3P-Matrix [--backup <settings.json>]
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync, readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const CAP_OVERFLOW = 100;                       // extra domains beyond MATRIX_OVERRIDES_CAP for the cap case

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-matrix-migration: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const load = (rel) => import(pathToFileURL(resolve(ext, rel)).href);

let C, normalizeState, buildMatrixRules, fromSettingsFile, SETTINGS_FORMAT, STATE_MIGRATIONS;
try {
  C = await load("data/constants.js");
  ({ normalizeState, STATE_MIGRATIONS } = await load("data/state-storage.js"));
  ({ buildMatrixRules } = await load("core/rule-builder.js"));
  ({ fromSettingsFile, SETTINGS_FORMAT } = await load("data/settings-io.js"));
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }

const ALL = C.MATRIX_SITE_ALL;
const { BLOCK, ALLOW } = C.MATRIX_ACTION;
const { SCRIPT, FRAME } = C.MATRIX_SCOPE;
const LEGACY_CODE = "code";                    // a pre-4.2 scope name — no longer a constant in the extension
const SCOPE_TYPES = Object.values(C.MATRIX_SCOPE).map((sc) => C.MATRIX_SCOPE_RESOURCE_TYPE[sc]);

let failed = 0;
function eq(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n     got      ${JSON.stringify(actual)}\n     expected ${JSON.stringify(expected)}`}`);
}
const rulesOf = (raw) => normalizeState({ matrixRules: raw }).matrixRules;

// Global storage + DNR output
const both = { [SCRIPT]: BLOCK, [FRAME]: BLOCK };
const g = normalizeState({ matrixRules: { [ALL]: { "a.example": both } } });
eq("global entry kept", g.matrixRules, { [ALL]: { "a.example": both } });
eq("DNR: one rule per scope, no initiator, PRIORITY.MATRIX",
   buildMatrixRules(g).map((r) => [r.priority, r.condition.initiatorDomains, r.condition.resourceTypes[0]]),
   SCOPE_TYPES.map((t) => [C.PRIORITY.MATRIX, undefined, t]));
eq("junk dropped", rulesOf({ [ALL]: { "not a host": both, "b.example": { [SCRIPT]: "nope" } } }), {});
eq("empty → {}", rulesOf(undefined), {});
eq("idempotent", normalizeState(g).matrixRules, g.matrixRules);
const many = {};
for (let i = 0; i < C.MATRIX_OVERRIDES_CAP + CAP_OVERFLOW; i++) many[`d${i}.example`] = { [SCRIPT]: BLOCK };
eq("cap = MATRIX_OVERRIDES_CAP", Object.keys(rulesOf({ [ALL]: many })[ALL]).length, C.MATRIX_OVERRIDES_CAP);

// Schema / migration list (C32)
eq("migrations ordered, last one reaches STATE_SCHEMA_VERSION",
   [STATE_MIGRATIONS.every((m, i) => i === 0 || m.to > STATE_MIGRATIONS[i - 1].to), STATE_MIGRATIONS.at(-1).to], [true, C.STATE_SCHEMA_VERSION]);
eq("normalized state carries STATE_SCHEMA_VERSION", normalizeState({}).schema, C.STATE_SCHEMA_VERSION);
eq("current-schema data is not migrated again (per-site key dropped)",
   normalizeState({ schema: C.STATE_SCHEMA_VERSION, matrixRules: { "site.example": { "x.example": both } } }).matrixRules, {});

// Removed in 4.5.4 (removal scheduled for 4.5): old shapes are dropped, never half-converted
eq("removed schema-2 conversion: per-site key dropped", rulesOf({ "site.example": { "c.example": both } }), {});
eq("removed schema-2 conversion: legacy { code } entry dropped", rulesOf({ [ALL]: { "e.example": { [LEGACY_CODE]: BLOCK } } }), {});
eq("removed schema-2 conversion: global entries of old data kept", rulesOf({ [ALL]: { "c.example": both }, "site.example": { "x.example": both } }), { [ALL]: { "c.example": both } });
{
  let error = "";
  try { fromSettingsFile({ format: SETTINGS_FORMAT, state: { level: C.LEVEL.HIGH } }); } catch (e) { error = e.message; }
  eq("removed v1 backup format: refused with a message, not imported", error !== "", true);
}

// schema 4 (4.4.5): a lock on a bare shared-hosting suffix is dropped, a tenant lock stays
{
  const [suffix] = C.SHARED_HOSTING_SUFFIXES;
  const tenant = "acme-my." + suffix;
  const s4 = normalizeState({ schema: 3, siteLocks: { [suffix]: C.LEVEL.ALLOW_ALL, [tenant]: C.LEVEL.HIGH, "other.example": C.LEVEL.SMART },
                              siteLocksOrder: [suffix, tenant, "other.example"] });
  eq("schema 4: bare shared-suffix lock dropped", Object.keys(s4.siteLocks).sort(), [tenant, "other.example"].sort());
  eq("schema 4: lock order kept in sync", s4.siteLocksOrder, [tenant, "other.example"]);
  eq("schema 4: idempotent on current data", normalizeState(s4).siteLocks, s4.siteLocks);
}

// Optional: a real backup file — every rule must end up global, none lost
const backup = arg("backup");
if (backup) {
  const raw = JSON.parse(readFileSync(backup, "utf8"));
  const before = new Set(Object.values(raw.settings?.showMatrixRules || {}).flatMap((m) => Object.keys(m)));
  const after = normalizeState(fromSettingsFile(raw)).matrixRules;
  eq("backup: only the global key remains", Object.keys(after).filter((k) => k !== ALL), []);
  eq("backup: every domain kept", Object.keys(after[ALL] || {}).sort(), [...before].sort());
}

console.log(failed ? `test-matrix-migration: ${failed} FAILED` : "test-matrix-migration: ALL PASS");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
