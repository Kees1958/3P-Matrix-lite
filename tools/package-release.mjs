#!/usr/bin/env node
// ── tools/package-release.mjs ─────────────────────────────────────────────────
// 5.0.7 — THE declaration of what each of the three release zips may hold (Xplainer audit, Ground Rules
// "Exactly three release zips" + B4), and the guard that enforces it BEFORE zipping. Before 5.0.7 the rule
// existed only in prose: the extension zip shipped README.md and a duplicate docs/STYLE_GUIDE.md.
//
//   extension  runtime code only (RUNTIME_EXTENSIONS) + the text files a user or a licence needs
//              (EXTENSION_TEXT_FILES). No changelog, no README, no other doc — every release edits those,
//              and an edited file inside the package disqualifies Chrome Web Store skip-review.
//   docs       project history: both changelogs (B4), README (architecture), style guide, analyses.
//   tools      build / verification / test suite (never uploaded).
// Version congruence (B4): CHANGELOG.md's top "## x.y.z" = manifest.json "version"; CHANGELOG_HISTORY.md
// has a "**tools x.y.z:**" line for tools/package.json's version.
//
// Consumers: tools/package-release-state.mjs (refuses to record a release whose trees fail this guard),
// tools/complete-check.mjs (step release-contents).
//
// Layouts (5.0.9, tools/repo-layout.mjs): the release layout (three sibling folders) and the repo layout (the
// extension is the repo root, the docs are its other top-level files, tools/ is this package) give the SAME three
// file lists — releaseTrees() is the one place that cuts them; package-release-state.mjs hashes exactly these.
//
// Usage:  node package-release.mjs [--extension <folder>] [--docs <folder>] [--tools .]
//         (defaults: repo-layout.mjs defaultRoots() — the repo root, or ../3P-Matrix + ../3P-Matrix-docs)
// Exit:   0 = every tree as declared · 1 = problem found · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, resolve, dirname, sep, extname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { EXTENSION_TEXT_FILES, defaultRoots, isSameRoot, listExtensionFiles, listDocsFiles, docsZipName } from "./repo-layout.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const HERE = dirname(fileURLToPath(import.meta.url));
export const MANIFEST_FILE = "manifest.json";
export const CHANGELOG_FILE = "CHANGELOG.md";
export const CHANGELOG_HISTORY_FILE = "CHANGELOG_HISTORY.md";
export const CHANGELOG_VERSION_RE = /^##\s+(\d+\.\d+\.\d+)\b/m;           // first "## x.y.z" heading
export const SKIP_NAMES = Object.freeze(new Set([".DS_Store", "Thumbs.db", ".git", "node_modules"]));   // never part of a release
const TOOLS_PACKAGE_FILE = "package.json";
const RUNTIME_EXTENSIONS = Object.freeze([".js", ".html", ".css", ".png", ".json"]);
const DOCS_REQUIRED = Object.freeze([CHANGELOG_FILE, CHANGELOG_HISTORY_FILE, "README.md"]);
const TOOLS_REQUIRED = Object.freeze([TOOLS_PACKAGE_FILE, "package-lock.json"]);
function toolsHistoryLine(version) { return `**tools ${version}:**`; }

// Every file under root as a path relative to root ("/" separators), SKIP_NAMES left out.
export function listTree(root, dir = root) {
  return readdirSync(dir).flatMap((n) => {
    if (SKIP_NAMES.has(n)) return [];
    const p = join(dir, n);
    return statSync(p).isDirectory() ? listTree(root, p) : [relative(root, p).split(sep).join("/")];
  });
}

// The three release file lists, for either layout: entries { name, path } — name = the path inside the zip
// ("/" separators), path = the file on disk. Release layout: each folder whole (a stray file then shows up — and
// fails the guard below). Repo layout (extension and docs are one folder): the extension's files and the top-level
// documents, as declared in repo-layout.mjs (incl. DOCS_ZIP_NAMES: ARCHITECTURE.md is the docs zip's README.md).
export function releaseTrees({ extension, docs, tools }) {
  const entry = (root, rename = (n) => n) => (p) => ({ name: rename(relative(root, p).split(sep).join("/")), path: p });
  const whole = (root) => listTree(root).sort().map((rel) => ({ name: rel, path: join(root, rel) }));
  const repo = isSameRoot(extension, docs);
  const byName = (a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  return {
    extension: repo ? listExtensionFiles(extension).map(entry(extension)) : whole(extension),
    docs:      repo ? listDocsFiles(docs, extension).map(entry(docs, docsZipName)).sort(byName) : whole(docs),
    tools:     whole(tools)
  };
}

// Returns the list of problems (empty = as declared). Pure apart from reading the three trees.
export function guardRelease({ extension, docs, tools }) {
  const problems = [];
  const trees = releaseTrees({ extension, docs, tools });
  for (const { name: f } of trees.extension) {
    if (EXTENSION_TEXT_FILES.includes(f)) continue;
    if (!RUNTIME_EXTENSIONS.includes(extname(f).toLowerCase())) problems.push(`extension: "${f}" is not runtime code and not a declared licence file — it belongs in the docs zip (or in EXTENSION_TEXT_FILES with a reason)`);
  }
  for (const f of EXTENSION_TEXT_FILES) if (!existsSync(join(extension, f))) problems.push(`extension: declared file "${f}" is missing`);
  for (const f of DOCS_REQUIRED) if (!trees.docs.some((e) => e.name === f)) problems.push(`docs: required file "${f}" is missing`);
  for (const f of TOOLS_REQUIRED) if (!existsSync(join(tools, f))) problems.push(`tools: required file "${f}" is missing`);
  if (problems.length) return problems;

  const extVersion = JSON.parse(readFileSync(join(extension, MANIFEST_FILE), "utf8")).version;
  const top = (readFileSync(join(docs, CHANGELOG_FILE), "utf8").match(CHANGELOG_VERSION_RE) || [])[1];
  if (top !== extVersion) problems.push(`docs: ${CHANGELOG_FILE} top entry is ${top || "missing"}, manifest.json says ${extVersion}`);
  const toolsVersion = JSON.parse(readFileSync(join(tools, TOOLS_PACKAGE_FILE), "utf8")).version;
  if (!readFileSync(join(docs, CHANGELOG_HISTORY_FILE), "utf8").includes(toolsHistoryLine(toolsVersion))) {
    problems.push(`docs: ${CHANGELOG_HISTORY_FILE} has no "${toolsHistoryLine(toolsVersion)}" line (B4: every tools version is recorded)`);
  }
  return problems;
}

// ── CLI (only when run directly, not when imported) ─────────────────────────
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`package-release: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const fallback = defaultRoots(HERE);
  const roots = { extension: arg("extension") || fallback.extension, docs: arg("docs") || fallback.docs, tools: arg("tools") || HERE };
  if (!roots.extension || !existsSync(join(roots.extension, MANIFEST_FILE))) didNotRun("missing or invalid --extension <folder>");
  if (!roots.docs || !existsSync(roots.docs)) didNotRun("missing or invalid --docs <folder>");
  const problems = guardRelease({ extension: resolve(roots.extension), docs: resolve(roots.docs), tools: resolve(roots.tools) });
  if (problems.length) {
    console.log(`package-release: FAIL — ${problems.length} problem(s):`);
    problems.forEach((p) => console.log(`  ${p}`));
    process.exit(EXIT.FOUND);
  }
  console.log("package-release: PASS — extension holds runtime code + declared licence files only; docs and tools complete; versions congruent");
  process.exit(EXIT.OK);
}
