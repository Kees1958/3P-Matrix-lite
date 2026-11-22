"use strict";

/**
 * 3P Matrix (4.5.4): this list ships as a precompiled JSON string in GovSuffixes.default.js, rebuilt by
 * 3P-Matrix-tools/gen-brands-data.mjs (registered in its data-sources.json; source: curated (tables in tools/gen-brands-data.mjs)).
 * EXTENSION/data/… paths below describe DownloadSentinel's own repository layout.
 *
 * GovSuffixes.js — Restricted public-suffix labels that only a verified
 * government body can register under (e.g. "gov.uk", "gov.br"): the
 * registry itself gatekeeps these, so a registered domain ending in one
 * of them ("example.gov.uk") IS a real government site by construction —
 * nobody else can register there. v3.3.0 (3P Matrix alignment item 17).
 *
 * Runtime use: protection/LookalikeDomainCheck.js exempts any domain whose
 * suffix matches this list from look-alike/brand-impersonation scoring,
 * so a real .gov.xx site is never flagged as "resembling" a known brand
 * or top site. This does NOT weaken protection against a domain merely
 * imitating a gov suffix in its own name (e.g. "my-gov.uk.evil.com" has a
 * suffix of "evil.com", not "gov.uk" — it still gets scored normally).
 *
 * Previously build-time only (tools/build-top-sites-filter.mjs, folding
 * these into the top-sites Bloom filter) — this wrapper adds a runtime
 * import so the same list can be consulted directly, not just via the
 * (lossy, no-exact-suffix-match) Bloom filter.
 *
 * Single source of truth: EXTENSION/data/GovSuffixes.json. See that file's
 * provenance note in tools/gen-brands-data.mjs.
 */
import { GovSuffixesDefaultJson } from "./GovSuffixes.default.js";
import { createListSetModule } from "./ListSetModule.js";

export const GovSuffixes = createListSetModule(GovSuffixesDefaultJson);
