// ── tools/repo-layout.mjs ─────────────────────────────────────────────────────
// 5.0.9 — THE declaration of where the extension, the docs and the tools are, for both layouts this package runs in
// (C21: one declaration; every default folder and every walker of the extension tree takes it from here):
//
//   repo layout     (GitHub, since 5.0.8's "lay out like uBlock Dynamic"): <repo>/ is the extension AND holds the
//                   project documents at its top level; this package is <repo>/tools/.
//   release layout  (the three zips unpacked side by side): 3P-Matrix/ · 3P-Matrix-docs/ · 3P-Matrix-tools/ (this).
//
// In the repo layout a top-level file belongs to the extension only when it is in EXTENSION_ROOT_FILES; every other
// top-level file is a document (docs zip) or repo housekeeping (REPO_ONLY_FILES). Folders in NON_EXTENSION_DIR_NAMES
// are never extension code in either layout.
//
// Public interface:
//   defaultRoots(toolsDir)              → { layout, extension, docs } — used when --extension / --docs are not given
//   isSameRoot(a, b)                    → true when extension and docs are the same folder (repo layout)
//   listExtensionFiles(ext, opts)       → absolute paths of the extension's files
//                                         opts: { skipDirs: [names], exts: [".js", …] } (both optional)
//   listDocsFiles(docs, ext)            → absolute paths of the docs' files (repo layout: the top-level documents)
//   docsZipName(name)                   → the name a repo-layout document has in the docs zip (DOCS_ZIP_NAMES)
// Dependencies: none (node:fs, node:path). State owned: none.
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, relative, sep } from "node:path";

// ── Settings (one place) ─────────────────────────────────────────────────────
export const LAYOUT = Object.freeze({ REPO: "repo", RELEASE: "release" });
export const RELEASE_EXTENSION_FOLDER = "3P-Matrix";
export const RELEASE_DOCS_FOLDER = "3P-Matrix-docs";
export const TOOLS_DIR_NAME = "tools";
const MANIFEST_FILE = "manifest.json";
// Folders that are never extension code (this package inside the repo, dependencies, version control).
export const NON_EXTENSION_DIR_NAMES = Object.freeze(new Set([TOOLS_DIR_NAME, "node_modules", ".git"]));
// The only top-level files the extension ships (runtime entry points + the licence texts a user needs).
export const EXTENSION_TEXT_FILES = Object.freeze(["LICENSE.txt", "THIRD_PARTY_LICENSES.md"]);
export const EXTENSION_ROOT_FILES = Object.freeze([MANIFEST_FILE, "background.js", ...EXTENSION_TEXT_FILES]);
// Top-level files of the repo that belong to no release zip: housekeeping, the GitHub/Web Store front page and
// privacy policy (README.md, privacy.md), and the programming-principles PDF (uploaded to the repo only).
export const REPO_ONLY_FILES = Object.freeze([".gitignore", ".gitattributes", "README.md", "privacy.md"]);
const REPO_ONLY_RE = /\.pdf$/i;
// Documents whose name in the repo differs from their name in the docs zip (repo name → zip name): the docs
// README (architecture) is ARCHITECTURE.md in the repo, because README.md is the repo's front page.
export const DOCS_ZIP_NAMES = Object.freeze({ "ARCHITECTURE.md": "README.md" });
const OS_LITTER = Object.freeze(new Set([".DS_Store", "Thumbs.db"]));

export function defaultRoots(toolsDir) {
  const up = resolve(toolsDir, "..");
  if (existsSync(join(up, MANIFEST_FILE))) return { layout: LAYOUT.REPO, extension: up, docs: up };
  return { layout: LAYOUT.RELEASE, extension: join(up, RELEASE_EXTENSION_FOLDER), docs: join(up, RELEASE_DOCS_FOLDER) };
}

export function isSameRoot(a, b) { return !!a && !!b && resolve(a) === resolve(b); }

function walk(dir, skip, out) {
  for (const name of readdirSync(dir)) {
    if (OS_LITTER.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (!skip.has(name)) walk(p, skip, out); }
    else out.push(p);
  }
  return out;
}

export function listExtensionFiles(ext, { skipDirs = [], exts = null } = {}) {
  const root = resolve(ext);
  const skip = new Set([...NON_EXTENSION_DIR_NAMES, ...skipDirs]);
  return walk(root, skip, [])
    .filter((p) => relative(root, p).includes(sep) || EXTENSION_ROOT_FILES.includes(relative(root, p)))
    .filter((p) => !exts || exts.some((e) => p.endsWith(e)))
    .sort();
}

export function listDocsFiles(docs, ext) {
  const root = resolve(docs);
  if (!isSameRoot(docs, ext)) return walk(root, NON_EXTENSION_DIR_NAMES, []).sort();
  return readdirSync(root)
    .filter((n) => !OS_LITTER.has(n) && !EXTENSION_ROOT_FILES.includes(n) && !REPO_ONLY_FILES.includes(n) && !REPO_ONLY_RE.test(n))
    .map((n) => join(root, n))
    .filter((p) => statSync(p).isFile())
    .sort();
}

export function docsZipName(name) { return DOCS_ZIP_NAMES[name] || name; }
