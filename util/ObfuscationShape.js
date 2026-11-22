// ── util/ObfuscationShape.js ────────────────────────────────────────────────────
// Single source of truth for the "does this string look like obfuscated code"
// test shared by blockObfuscatedEval/Function/SetTimeout/SetInterval (security/sec-noeval.js, sec-nofunction.js,
// sec-nosettimeout.js, sec-nosetinterval.js).
//
// Those four files are MAIN-world content scripts (document_start, run inside the
// page) and so CANNOT import this module — chrome.scripting injects them as
// classic scripts, not ES modules (see ARCHITECTURE.md, security/ section). Each
// one therefore carries its OWN inlined copy of OBFUSCATION_CONFIG and
// detectObfuscation() below, byte-for-byte. This module is what that copy is
// copied FROM, and what keeps it honest:
//   - tools/check-shipped-terms.mjs imports this module and fails if any
//     sec-no*.js file's inlined thresholds/logic drift from it (single source +
//     mechanical guard, same pattern as the LOG_PREFIX check in that tool).
//   - tools/test-obfuscation-shape.mjs unit-tests detectObfuscation() itself,
//     directly, with node:test — the inlined copies run the identical code, so
//     testing this module tests them.
//
// Detection shape (4.4.3): a *string* payload is flagged only when it matches a
// recognized obfuscation pattern — a Dean Edwards packer bootstrap, a base64
// blob long enough to be a real payload (not a short token), a char-code array
// long enough to be a real string (not one or two characters), or enough
// `_0x..`-style renamed identifiers to be obfuscator.io output rather than one
// coincidental hex-looking name. Presence of the sink alone (a plain string, a
// short literal, a function reference) is never enough — see the "don't flag by
// itself" cases in each sink's own test suite.
//
// Public interface:
//   OBFUSCATION_CONFIG                  — thresholds, one place (B1)
//   detectObfuscation(payload) -> reason string, or null if it should pass through
// ─────────────────────────────────────────────────────────────────────────────

export const OBFUSCATION_CONFIG = Object.freeze({
  // Minimum length of a base64 literal passed to atob() before it's treated as
  // a real encoded payload rather than a short, ordinary token/config value.
  MIN_B64_LEN: 40,
  // Minimum count of numeric arguments to String.fromCharCode() before it's
  // treated as a real encoded string rather than one or two ordinary characters.
  MIN_CHARCODE_ARGS: 10,
  // Minimum count of `_0x..`-style identifiers before it's treated as real
  // obfuscator.io renaming rather than one coincidental hex-looking name.
  MIN_HEX_IDENTS: 3
});

const PACKER_RE   = /eval\(function\(p,a,c,k,e,d/;
const HEX_IDENTS_RE = /_0x[0-9a-f]{4,6}/g;
const B64_ATOB_RE = new RegExp(`atob\\(\\s*['"][A-Za-z0-9+/=]{${OBFUSCATION_CONFIG.MIN_B64_LEN},}['"]\\s*\\)`);
const CHAR_CODE_RE = new RegExp(
  `String\\.fromCharCode\\(\\s*(?:\\d+\\s*,\\s*){${OBFUSCATION_CONFIG.MIN_CHARCODE_ARGS - 1},}\\d+\\s*\\)`
);

function countHexIdents(s) {
  let n = 0;
  HEX_IDENTS_RE.lastIndex = 0;
  while (n < OBFUSCATION_CONFIG.MIN_HEX_IDENTS && HEX_IDENTS_RE.exec(s) !== null) n += 1;
  HEX_IDENTS_RE.lastIndex = 0;
  return n;
}

// Returns a short reason string when the payload looks obfuscated, or null when
// it should be allowed through unmodified. Pure — no DOM/chrome access, so the
// inlined copies run it against captured-native regex internals instead (see
// each sec-no*.js's own "Captured builtins" section); the logic is identical.
export function detectObfuscation(payload) {
  const s = String(payload);
  if (PACKER_RE.test(s)) return "packer";
  if (B64_ATOB_RE.test(s)) return "base64-blob";
  if (CHAR_CODE_RE.test(s)) return "char-code-array";
  if (countHexIdents(s) >= OBFUSCATION_CONFIG.MIN_HEX_IDENTS) return "hex-identifiers";
  return null;
}
