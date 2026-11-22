"use strict";

/**
 * 3P Matrix (4.5.4): this list ships as a precompiled JSON string in UrlShorteners.default.js, rebuilt by
 * 3P-Matrix-tools/build-curated-lists.mjs (registered in its data-sources.json; source: curated (tools/lists-src/UrlShorteners.json)).
 * EXTENSION/data/… paths below describe DownloadSentinel's own repository layout.
 *
 * UrlShorteners.js — Well-known URL-shortener domains (heuristics plan
 * "Later steps", v2.11.0).
 *
 * Deliberately NOT a block signal: shorteners are used constantly for
 * entirely legitimate purposes (social media character limits, marketing
 * links, QR codes), so a hit here is informational/contextual only — see
 * SCORING_CONFIG.URL_SHORTENER_SCORE in protection/ScoringEngineV2.js for
 * how mild the resulting score is, and why it never fires on its own as a
 * hard warning.
 *
 * Each entry is the shortener's own registered domain (eTLD+1, lowercase).
 *
 * DOCS/ARCHITECTURE.md, "Filter-data remote-update mechanism" — the list now
 * lives in EXTENSION/data/UrlShorteners.json (single source of truth; "to
 * add a shortener: add it there only"); this module only holds the small
 * `.set` convenience derivation (shared with BrandDomains.js via
 * ListSetModule.js — same shape, same factory). See SuspiciousDomains.js's
 * header for the full rationale behind the default/remote split.
 */
import { UrlShortenersDefaultJson } from "./UrlShorteners.default.js";
import { createListSetModule } from "./ListSetModule.js";

export const UrlShorteners = createListSetModule(UrlShortenersDefaultJson);
