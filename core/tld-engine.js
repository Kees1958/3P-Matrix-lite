// ── core/tld-engine.js ────────────────────────────────────────────────────────
// Pure TLD computation: derives the safer-regions TLD list from browser
// language settings, user preferences and the auto-add mode. (The level 2 TLD
// blocklist is the generated HaGeZi list in data/spam-tlds.js — not built here.)
// No Chrome API calls, no DOM access, no side effects. (The browser's time zone,
// the one environmental input, is passed IN by the caller — never read here —
// so every function below stays a deterministic input → output mapping.)
//
// Public interface:
//   rebuildTldList(mode, browserLangs, manualTlds, excludedTlds, cb, timeZone) — builds full merged TLD whitelist
//   AUTO_TLD_MODE — the four auto-add scopes (NONE/BROWSER/CONTINENT/WORLDWIDE); 3P Matrix uses
//                   CONTINENT only (data/constants.js SAFER_REGIONS_AUTO_MODE) — no slider since 0.2.4
//   BASE_TLDS — the whitelist's default starting set, included like any other entry (NOT
//               protected from excludedTlds — "default" means something that can be
//               restored to, not enforced). Single source of truth — data/state-storage.js's
//               DEFAULT_STATE.tlds imports this directly rather than duplicating it.
//
// How the four auto-add scopes work (see computeAutoTlds):
//   NONE       nothing added automatically.
//   BROWSER    the countries named by the browser's language tags (nl-BE → .be, plus the
//              small hand-picked helpers below: region pairings, bare-language defaults, .eu).
//   CONTINENT  BROWSER, plus every country ON THE USER'S CONTINENT that speaks any of the
//              browser's languages — or a language readable by its speakers (Danish →
//              Norwegian/Swedish, Czech ↔ Slovak, …; Portuguese → Spanish, one way only;
//              see MUTUALLY_INTELLIGIBLE_LANGS and ONE_WAY_INTELLIGIBLE_LANGS). The continent comes from the first language tag that
//              names a usable region; if none does, from the browser time zone; if that
//              fails too, nothing is added beyond BROWSER.
//   WORLDWIDE  BROWSER, plus every country in the world that speaks any of the browser's
//              languages or a readable relative of one.
// "Speaks" comes from data/country-data.js — one source of truth, no per-language tables here.
//
// computeAutoTlds() is internal-only — called by rebuildTldList(), not used elsewhere.
// ─────────────────────────────────────────────────────────────────────────────

import { EU_LANGS, AUTO_TLD_MODE, BASE_TLDS } from "../data/tld-constants.js";
import {
  COUNTRY_DATA, TERRITORY_DATA, REGION_TLD_EXCEPTIONS, LANG_ALIASES, EXPANSION_EXCLUDED_TLDS,
  MUTUALLY_INTELLIGIBLE_LANGS, ONE_WAY_INTELLIGIBLE_LANGS,
  TIMEZONE_AREA_DEFAULT, TIMEZONE_PREFIX_EXCEPTIONS, TIMEZONE_EXCEPTIONS
} from "../data/country-data.js";

// AUTO_TLD_MODE and BASE_TLDS live in data/tld-constants.js (4.2.3) and are re-exported here.
export { AUTO_TLD_MODE, BASE_TLDS };

// Explicit mapping from a bare 2-letter language code to its most likely default country.
// Used ONLY when the browser reports a language with no region subtag (e.g. "nl" not "nl-NL").
// Languages are omitted here when the language code does not reliably imply one specific country.
//
// Why this matters: language code != country code in many cases. For example "sv" is the
// ISO code for Swedish, but "sv" is also the ccTLD for El Salvador — without this map, a
// bare "sv" browser language would silently add El Salvador's TLD.
const LANG_DEFAULT_COUNTRY = {
  "nl": "nl", "de": "de", "it": "it", "pl": "pl",
  "da": "dk", "fi": "fi", "el": "gr", "hu": "hu", "cs": "cz",
  "sk": "sk", "hr": "hr", "bg": "bg", "tr": "tr",
  "th": "th", "vi": "vn", "id": "id", "ja": "jp", "ko": "kr",
  "he": "il", "hi": "in"
  // Omitted (ambiguous without a region subtag):
  //   sv — Swedish ≠ El Salvador's "sv" ccTLD; needs "sv-SE"
  //   no — kept out for consistency
  //   zh — could be CN, TW, HK, SG
  //   uk — Ukrainian language, "uk" ccTLD is United Kingdom — never auto-guess
  //   ar — could be any of 20+ Arabic-speaking countries
};

// World languages spoken across many countries where readers commonly consume sources
// from several countries interchangeably. Bare language tags (no region subtag, e.g. "en"
// instead of "en-US") add this small cluster of most-read source countries.
const LANG_WORLD_DEFAULTS = {
  "en": ["uk", "us", "ie", "au", "ca", "nz"],   // BBC/UK, CNN/NYT/US, Ireland, Australia, Canada, New Zealand
                                               // (3P Matrix 0.2.4: nz added — completes the Five Eyes; not in
                                               // 3P-Matrix-lite / uBlock Stripped Dynamic)
  "fr": ["fr", "be", "ca"],               // France, Belgium, Canada (Quebec)
  "es": ["es", "mx", "ar"]                // Spain, Mexico, Argentina — three largest sources
};

// Hand-picked region-pairing table. Used only when the browser supplies a language WITH
// a region subtag (e.g. "en-IE", "en-US", "da-FO"). A pairing is added only when the
// region has its own distinct national identity and users there commonly read both their
// own region's sources and the larger parent country's sources.
// Format: "lang-REGION" -> [extra country code to add alongside the region itself]
const REGION_PAIRINGS = {
  "en-ie": ["uk"],   // Ireland <-> UK
  "en-uk": ["us"],   // UK <-> US
  "en-gb": ["us"],
  "en-us": ["uk"],
  "da-fo": ["dk"],   // Faroe Islands <-> Denmark
  "en-im": ["uk"],   // Isle of Man <-> UK
  "fr-ca": ["fr"],   // Canadian French <-> France
  "es-mx": ["es"],   // Mexican Spanish <-> Spain
  "pt-br": ["pt"]    // Brazilian Portuguese <-> Portugal
};

// EU_LANGS is loaded from data/tld-constants.js (single source of truth).

// ── Lookups derived once, at load, from data/country-data.js ────────────────
// COUNTRY_INDEX: ccTLD → { continent, langs:Set of canonical language codes }.
// REGION_TO_TLD: region subtag ("be", "gb") → ccTLD ("be", "uk").
function normLang(tag) {
  const base = String(tag || "").toLowerCase().split("-")[0];
  return LANG_ALIASES[base] || base;
}
const COUNTRY_INDEX = new Map();
const REGION_TO_TLD = Object.assign({}, REGION_TLD_EXCEPTIONS);
[COUNTRY_DATA, TERRITORY_DATA].forEach(function(byContinent) {
  Object.keys(byContinent).forEach(function(continent) {
    Object.keys(byContinent[continent]).forEach(function(tld) {
      COUNTRY_INDEX.set(tld, { continent: continent, langs: new Set(byContinent[continent][tld].map(normLang)) });
      if (!(tld in REGION_TO_TLD)) REGION_TO_TLD[tld] = tld;
    });
  });
});
const EXPANSION_EXCLUDED = new Set(EXPANSION_EXCLUDED_TLDS);

// RELATED_LANGS: canonical language → the other languages its speakers can also read.
// Built from the symmetric groups (every member → every other member) and the
// one-way pairs (reader → readable language only).
const RELATED_LANGS = new Map();
function addRelation(from, to) {
  if (from === to) return;
  if (!RELATED_LANGS.has(from)) RELATED_LANGS.set(from, new Set());
  RELATED_LANGS.get(from).add(to);
}
MUTUALLY_INTELLIGIBLE_LANGS.forEach(function(group) {
  const members = group.map(normLang);
  members.forEach(function(lang) { members.forEach(function(other) { addRelation(lang, other); }); });
});
ONE_WAY_INTELLIGIBLE_LANGS.forEach(function(pair) { addRelation(normLang(pair[0]), normLang(pair[1])); });

// Browser time zone ("Europe/Amsterdam") → continent, or null when it can't tell
// (missing/odd zone, "UTC", Antarctica). Exact name first, then prefix, then area.
function continentFromTimeZone(timeZone) {
  if (!timeZone || typeof timeZone !== "string") return null;
  if (TIMEZONE_EXCEPTIONS[timeZone]) return TIMEZONE_EXCEPTIONS[timeZone];
  const prefixes = Object.keys(TIMEZONE_PREFIX_EXCEPTIONS);
  for (let i = 0; i < prefixes.length; i++) {
    if (timeZone.indexOf(prefixes[i]) === 0) return TIMEZONE_PREFIX_EXCEPTIONS[prefixes[i]];
  }
  return TIMEZONE_AREA_DEFAULT[timeZone.split("/")[0]] || null;
}

// Which continent does this browser live on? The first language tag whose region
// subtag maps to a known country decides (browsers list languages in preference
// order, so that is the user's own locale); tags with an unusable region (es-419)
// are skipped. Only if no tag helps does the time zone get a say.
const LANG_TAG_MIN_PARTS = 2;            // "nl-NL": language + region
function resolveHomeContinent(browserLangs, timeZone) {
  for (let i = 0; i < browserLangs.length; i++) {
    const parts = String(browserLangs[i]).toLowerCase().split("-");
    if (parts.length < LANG_TAG_MIN_PARTS) continue;              // no region subtag
    const info = COUNTRY_INDEX.get(REGION_TO_TLD[parts[parts.length - 1]]);
    if (info) return info.continent;
  }
  return continentFromTimeZone(timeZone);
}

// CONTINENT / WORLDWIDE: starts from the BROWSER-level countries, then adds every
// country (in the user's continent, or anywhere) that speaks any browser language.
function expandByLanguage(mode, browserLangs, seedCountries, timeZone) {
  const result = seedCountries.slice();
  let continent = null;
  if (mode === AUTO_TLD_MODE.CONTINENT) {
    continent = resolveHomeContinent(browserLangs, timeZone);
    if (!continent) return result; // guard: home continent unknown — add nothing beyond BROWSER
  }
  // Every browser language, plus the languages readable by its speakers.
  const spoken = new Set();
  browserLangs.forEach(function(tag) {
    const lang = normLang(tag);
    spoken.add(lang);
    (RELATED_LANGS.get(lang) || []).forEach(function(related) { spoken.add(related); });
  });
  COUNTRY_INDEX.forEach(function(info, tld) {
    if (continent && info.continent !== continent) return;
    if (EXPANSION_EXCLUDED.has(tld) || result.indexOf(tld) !== -1) return;
    for (const lang of info.langs) {
      if (spoken.has(lang)) { result.push(tld); return; }
    }
  });
  return result;
}

// Computes auto-detected TLDs from browser language settings and the chosen scope mode.
// mode: an AUTO_TLD_MODE value. timeZone: the browser's IANA zone name, used only by
// CONTINENT mode as a fallback (optional — "" or undefined simply means "no guess").
// Calls cb(tlds) with an array of TLD strings.
function computeAutoTlds(mode, browserLangs, cb, timeZone) {
  if (mode === AUTO_TLD_MODE.NONE) { cb([]); return; }
  const browserCountries = [];
  let hasEuLang = false;
  browserLangs.forEach(function(lang) {
    const parts = lang.toLowerCase().split('-');
    const lc = parts[0];
    if (EU_LANGS[lc]) hasEuLang = true;

    if (parts.length > 1) {
      // Explicit region subtag present (e.g. "nl-BE" -> "be") — use it directly.
      const region = parts[parts.length - 1];
      const regionTld = REGION_TO_TLD[region] || region; // en-GB → "uk", not "gb"
      if (/^[a-z]{2,3}$/.test(region) && browserCountries.indexOf(regionTld) === -1)
        browserCountries.push(regionTld);
      // Check the hand-picked region-pairing table for a companion country.
      const pairKey = lc + '-' + region;
      if (REGION_PAIRINGS[pairKey]) {
        REGION_PAIRINGS[pairKey].forEach(function(c) {
          if (browserCountries.indexOf(c) === -1) browserCountries.push(c);
        });
      }
    } else if (LANG_WORLD_DEFAULTS[lc]) {
      // Bare world-language tag — add the cluster of most-read source countries.
      LANG_WORLD_DEFAULTS[lc].forEach(function(c) {
        if (browserCountries.indexOf(c) === -1) browserCountries.push(c);
      });
    } else if (LANG_DEFAULT_COUNTRY[lc]) {
      // Bare tag for a language with one unambiguous default country.
      const dflt = LANG_DEFAULT_COUNTRY[lc];
      if (browserCountries.indexOf(dflt) === -1) browserCountries.push(dflt);
    }
  });
  if (hasEuLang && browserCountries.indexOf('eu') === -1) browserCountries.push('eu');
  if (mode === AUTO_TLD_MODE.BROWSER) { cb(browserCountries); return; }
  cb(expandByLanguage(mode, browserLangs, browserCountries, timeZone));
}

// Builds the full merged TLD whitelist from auto-detected, manual, and excluded TLDs.
// BASE_TLDS is the default starting set, not a protected floor — see the
// excludedTlds filter below, which applies to it like any other entry.
// Calls cb(tlds) with the final array.
export function rebuildTldList(mode, browserLangs, manualTlds, excludedTlds, cb, timeZone) {
  computeAutoTlds(mode, browserLangs, function(autoTlds) {
    let merged = BASE_TLDS.slice();
    autoTlds.forEach(function(t) { if (merged.indexOf(t) === -1) merged.push(t); });
    (manualTlds || []).forEach(function(t) { if (merged.indexOf(t) === -1) merged.push(t); });
    // Drop anything the user explicitly removed — nothing, including BASE_TLDS,
    // is protected from exclusion. A user who clears everything out can always
    // get back to the default list (BASE_TLDS + Continent country codes) via
    // ui/popup.js's "Default" button.
    if (excludedTlds && excludedTlds.length) {
      merged = merged.filter(function(t) { return excludedTlds.indexOf(t) === -1; });
    }
    cb(merged);
  }, timeZone);
}
