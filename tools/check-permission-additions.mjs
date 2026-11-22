#!/usr/bin/env node
// ── tools/check-permission-additions.mjs ─────────────────────────────────────────
// C36 (least privilege, 5.0.7): the manifest may not gain a permission the previous release did not ship unless
// the addition is approved below with its reason. "Previous release" = the extension record in
// package-release-state.json, which tools/package-release-state.mjs writes at packaging time — so before a
// release it holds the LAST shipped permissions, after packaging it holds the new ones.
// Removed permissions are reported (good news), never a failure.
//
// Usage:  node check-permission-additions.mjs --extension ../3P-Matrix [--state package-release-state.json]
// Exit:   0 = no unapproved addition · 1 = unapproved addition · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST_FILE = "manifest.json";
const DEFAULT_STATE_FILE = join(HERE, "package-release-state.json");
const PERMISSION_KEYS = Object.freeze(["permissions", "host_permissions", "optional_permissions", "optional_host_permissions"]);
// Approved additions, each with its reason and the version that added it. Empty = nothing new may appear.
// Example shape: { "permissions:offscreen": "5.1.0 — VirusTotal hashing of large files needs an offscreen document" }
const APPROVED_ADDITIONS = Object.freeze({});

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`check-permission-additions: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function readJson(path, what) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch (e) { return didNotRun(`${what}: ${e.message}`); }
}
function flatten(lists) { return PERMISSION_KEYS.flatMap((k) => (Array.isArray(lists[k]) ? lists[k] : []).map((p) => `${k}:${p}`)); }

const ext = arg("extension");
const statePath = arg("state") || DEFAULT_STATE_FILE;
if (!ext || !existsSync(join(ext, MANIFEST_FILE))) didNotRun("missing or invalid --extension <folder>");
if (!existsSync(statePath)) didNotRun(`no previous release record (${statePath})`);
const state = readJson(statePath, "release record");
if (!state.extension || !state.extension.shippedPermissions) didNotRun("release record has no extension.shippedPermissions");

const before = new Set(flatten(state.extension.shippedPermissions));
const now = flatten(readJson(join(ext, MANIFEST_FILE), MANIFEST_FILE));
const added = now.filter((p) => !before.has(p));
const removed = [...before].filter((p) => !now.includes(p));
const unapproved = added.filter((p) => !APPROVED_ADDITIONS[p]);

removed.forEach((p) => console.log(`  info: ${p} removed since ${state.extension.version}`));
added.filter((p) => APPROVED_ADDITIONS[p]).forEach((p) => console.log(`  info: ${p} added — approved: ${APPROVED_ADDITIONS[p]}`));
if (unapproved.length) {
  console.log(`check-permission-additions: FAIL — ${unapproved.length} permission(s) not shipped by ${state.extension.version} and not approved:`);
  unapproved.forEach((p) => console.log(`  ${p} — add it to APPROVED_ADDITIONS with its reason, or remove it`));
  process.exit(EXIT.FOUND);
}
console.log(`check-permission-additions: PASS — ${now.length} permission entries, none added since ${state.extension.version} without approval`);
process.exit(EXIT.OK);
