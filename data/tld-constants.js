// ── data/tld-constants.js ─────────────────────────────────────────────────────
// Language/TLD tables needed by core/tld-engine.js (ported from 3P-Matrix-lite
// 4.0.2 data/constants.js). Pure constants.
//
// The TLD blocklist is NOT here: level 2+ uses the generated HaGeZi list
// (data/spam-tlds.js) only.
// ─────────────────────────────────────────────────────────────────────────────

// The auto-add scopes (3P-Matrix-lite's slider positions; 3P Matrix fixes CONTINENT,
// see data/constants.js SAFER_REGIONS_AUTO_MODE). Compare against these, never bare numbers.
// (4.2.3: moved here from core/tld-engine.js so the data layer never imports core — audit finding 7.)
export const AUTO_TLD_MODE = Object.freeze({ NONE: 0, BROWSER: 1, CONTINENT: 2, WORLDWIDE: 3 });

// Base TLDs included in the safer regions by default. These cover the most common
// legitimate third-party origins on the web — but, like every other entry,
// a user can exclude any of them via excludedTlds; nothing here is
// permanently protected. The popup's "Default" button is what restores
// this starting set, not an enforced floor in the computation.
// 3P Matrix: "biz", "shop", "store", "site" and "online" removed from 3P-Matrix-lite's
// base set — all five are on the HaGeZi abused-TLD list / rated suspicious by
// DownloadSentinel, so they must never be part of the default safer regions.
// (4.2.3: moved here from core/tld-engine.js — audit finding 7.)
export const BASE_TLDS = Object.freeze(["com","net","org","info","io","co","ai","tech","app","cloud","tv","edu","gov"]);

// EU official languages — decides whether "eu" joins the safer regions.
export const EU_LANGS = {
  "bg":1,"hr":1,"cs":1,"da":1,"nl":1,"et":1,"fi":1,"fr":1,"de":1,"el":1,
  "hu":1,"ga":1,"it":1,"lv":1,"lt":1,"mt":1,"pl":1,"pt":1,"ro":1,"sk":1,"sl":1,"es":1,"sv":1
};
