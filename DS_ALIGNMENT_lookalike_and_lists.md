# DownloadSentinel — aligning the download-URL checks with 3P Matrix

**For:** DownloadSentinel 3.1.0 → next minor (3.2.0) · **Source of the decisions:** 3P Matrix design session 2026-10-19
(`claude/DESIGN_lookalike_check.md`) and the 3P Matrix 4.2.3 audit fixes.
**Status:** plan only — nothing changed in DownloadSentinel yet. Every DS reference below was checked against the
uploaded DS 3.1.0 extension/tools/docs.

## Why

3P Matrix vendors DownloadSentinel's heuristics (`lib/downloadsentinel/`, DS 3.0.4 + 2 marked patches). Both
extensions answer the same question — "is this host imitating a real site or brand?" — DS for a **download link's
host**, 3P Matrix for the **site being opened**. Keeping one design (and ideally one shared code base) means a fix or
a list update helps both. Today they differ in two patches, and both share three overlapping imitation checks
that the 3P Matrix session redesigned.

## 0. Already diverged — upstream the 3P Matrix patches into DS

| # | Where (DS 3.1.0) | 3P Matrix change | Why |
|---|---|---|---|
| 0.1 | `protection/SketchyUrlCheck.js` check 3 "Excessive subdomains" (`host.split(".")`, `> 3`) | count only labels **in front of the registered domain** (`UrlUtils.getRegisteredDomain`), fire at ≥ 3 (`EXCESSIVE_SUBDOMAIN_LABELS`) | `news.bbc.co.uk` and every `*.co.uk/.com.br` host counted multi-part public suffixes as "excessive" |
| 0.2 | `protection/CombinationScoring.js` `FAMILY_MAP` | `NonStandardPort: "HOST_IDENTITY"` | 3P Matrix-only signal; harmless to add, needed only if DS adds a port signal |

Everything else in the shared modules (`FilenameUrlHeuristics`, `BloomFilter`, `TopSitesFilter`, `UrlUtils`,
`PublicSuffixList`, `HostList`, `BrandDomains`) is identical between DS 3.1.0 and 3P Matrix 4.2.3.

## 1. Replace the three overlapping imitation checks with one look-alike check

**Today in DS (and 3P Matrix):**

| Check | DS location | List | Score |
|---|---|---|---|
| Generic digit-for-letter ("m1cr0s0ft") | `SketchyUrlCheck` check 5 `LOOKALIKE_CHAR` | none | +15 into the SketchyUrl score |
| Brand look-alike (bigram rn→m … whole name) | `FilenameUrlHeuristics.checkBrandHomoglyph` → `ScoringEngineV2` ~l.806 | `BrandDomains` (22) | `BRAND_HOMOGLYPH_SCORE` −65 |
| Top-site look-alike (one swap at a time) | `FilenameUrlHeuristics.checkLookalikeTopSite` → ~l.815 | `TopSitesFilter` (CrUX top 1M) | `LOOKALIKE_TOP_SITE_SCORE` −25 |

One trick ("paypa1") can fire two or three of these; the lists and swap rules disagree.

**New: one check (`protection/LookalikeDomainCheck.js`), applied to the download host** — the final URL's host and,
when the registered domain differs, the original URL's host too (worse of the two, the same pattern
`BrowserProtection.checkHostReputation` already uses for the DNS checks).

1. **Test 1 — the host itself is popular → stop.** Registered domain in the top-sites list (see §3) ⇒ an original,
   not an imitation. Especially important for downloads: CDN/storage hosts (githubusercontent.com,
   cloudfront.net, akamaized.net, googleapis.com …) are popular and must never be "look-alikes".
2. **Test 2 — no imitation characters → stop (this check only).**
   - *clear*: `1→l 0→o 5→s 8→b` **only when the digit touches a letter** (digit runs — 365, 500px, 1688, numbered
     mirrors like `download3` — are not imitations; the existing V2.4.1 boundary rule stays);
   - *non-Latin look-alike letters* (e.g. Cyrillic а): the URL API returns punycode (`xn--`), so decode the label
     (small RFC 3492 decoder — no browser API exists) and map confusables to Latin;
   - *questionable*: `rn→m vv→w cl→d`.
3. **Test 3 — convert and compare locally, multi-step** (first hit wins, duplicate variants skipped):
   1. all clear converted (skipped when there is none);
   2. all clear + 1st questionable occurrence (left to right);
   3. all clear + 2nd questionable occurrence;
   4. all clear + all questionable.

   Each variant is compared **two ways**:
   - *whole name* against the top-sites list — only when the converted name has **≥ 5 letters**
     (measured on CrUX 202609: below 5 letters accidental hits dominate — rnz→mz, tcl→td, e1→el; from 5 letters
     0.0–0.4 %, equal for clear and questionable kinds);
   - *separate words* (split on `-` and `.`) against the brand list (§2) — catches `microsoft-login`, `paypa1-l0gin`.
4. **Reason text:** "looks like paypal.com" (the matched brand's/site's real website).

**Scoring in DS** (DS holds the download while its online checks run, so the "warn first, check online in the
dialog" order of 3P Matrix becomes: the local hit is strong enough to warn on its own, the online results set the
severity):
- new `CombinationScoring.FAMILY_MAP` source `LookalikeDomain: "HOST_IDENTITY"` (same family as today's
  BrandHomoglyph/LookalikeTopSite, so it never stacks with a HostList/IP hit);
- brand match → `LOOKALIKE_BRAND_SCORE` −65 (today's BRAND_HOMOGLYPH level); top-site-only match →
  `LOOKALIKE_SITE_SCORE` −45 (stronger than today's −25: test 1 + the ≥5-letter rule remove most of the noise the
  −25 was compensating for) — both calibrated with `tools/fp-sweep.mjs` before release;
- remove `SketchyUrlCheck` check 5, `checkBrandHomoglyph`, `checkLookalikeTopSite` and their two scores
  (one release with both paths behind a constant switch if fp-sweep needs a side-by-side run).

**Stays separate (not imitation tricks):** plain typos without imitation characters ("paypall", "gooogle") via the
edit-distance check 4a; punycode check 2; brand-name-in-host check 4 (reworked in §2); all host-reputation, path,
filename, MIME and VirusTotal checks.

## 2. One brand list for every check (~600 websites)

- **Today:** `SketchyUrlCheck.BRANDS` (113, keyword + canonical + exceptions) and `BrandDomains` (22) grew separately;
  7 of the 22 are missing from the 113 (chase, wellsfargo, citibank, ebay, binance, steampowered, outlook).
- **New:** one data file `data/Brands.json` (+ generated default, same default/remote split as the other lists):
  `{ keyword, domains: [real websites], exceptions: [], wholeNameOnly }` — 534 keywords / 594 websites, built in
  the 3P Matrix session: 113 + 7 + regional extension (Five Eyes, Europe without Russia/Belarus, Middle America,
  South America, Korea, Japan) + parcel services, supermarkets ("free groceries" lures) and lotteries ("prize"
  lures). Every website verified in the CrUX 202609 top-1M list. The full table is in
  `claude/DESIGN_lookalike_check.md`.
- **Matching rules** (measured on a 215,348-site CrUX sample — real popular sites wrongly flagged by a brand
  signal):

  | Variant | False alarms |
  |---|---|
  | today: 113 brands, `host.includes(keyword)` | 1.05 % (worst: audi, meta, office, ups, google, bmw …) |
  | 534 brands, `includes()` | 2.45 % |
  | **534 brands, separate words + whole-name-only for short/ordinary words + typos only for ≥ 7 letters** | **0.82 %** |

  1. **Separate words instead of substring** in check 4 (`isBrandImpersonation`): split host on `.`/`-`; "apple" no
     longer matches "pineapple", "google" no longer matches "googleusercontent".
  2. **`wholeNameOnly`** for names under 5 letters and ordinary words (plus, target, free, orange, metro, spark,
     office, lotto, alpha, canada, posta, poste, ideal, island, discover, teams, post, coop, spar, dia, ica, linkt,
     mbank …): they count only when the registered name **is** the brand (imitated), never as a word inside it.
  3. **Fuzzy (edit-distance) check 4a only for keywords of ≥ 7 letters** (`FUZZY_MIN_BRAND_LENGTH` 5 → 7): the
     remaining 5–6-letter noise (linkt→link, mbank→bank, shopify↔spotify) disappears.
  4. Brands on shared government suffixes (gov.uk, gouv.fr, gov.br, gob.mx …) are exemption-only; agency names
     (impots, ameli, elster, irs, sat …) are the keywords.
  5. Most remaining false alarms are big brands' own country sites (google.de, amazon.co.uk) — removed by test 1
     ("host itself popular → stop"), which in DS should also gate checks 4/4a.

## 3. Top-sites list — top 100,000 + every brand website

- `tools/build-top-sites-filter.mjs`: add a CrUX **rank cut-off (≤ 100,000)** and **union the brand list's
  websites** (76 of the 594 are below the top 100k — smaller banks/post services such as snsbank.nl, knab.nl,
  triodos.nl, posta.sk). ≈ 80,000 registered domains, ≈ 125 KB instead of ≈ 1.2 MB, same Bloom parameters
  (1 % FP, `BloomFilter.sizeFor`). The 3P Matrix tool `update-top-sites.mjs` reproduces DS's build bit for bit
  (verified on 202609) — share one implementation.
- 3P Matrix loads the filter lazily (only when test 3 is reached); DS can keep its `FilterDataLoader` path.

## 4. Domain age — unknown counts as "younger than 90 days"

- `protection/RdapProtection.js` `scoreAge(null)` returns `{ score: 0, label: "Registration age unknown" }`.
  **Decided:** no published age is treated like 31–90 days (`−10`, "registration age not published — treated as
  recent"). RDAP does not always publish a date (e.g. DENIC .de; some ccTLDs have no RDAP at all).
- Thresholds stay 30 / 90 days.

## 5. Data lists — refresh once per minor release, enforced

- Add a register `tools/data-sources.json` (as in 3P Matrix tools 4.2.3): per list the source URL, licence, tool,
  source release, entry count and the extension **major.minor it was rebuilt for**, `updateOn: "minor"`.
- Add `tools/check-list-freshness.mjs` to `complete-check.mjs`: on a minor bump (3.1 → 3.2) it fails until each list
  was rebuilt; a patch (3.2.0 → 3.2.1) never requires it; it also fails when a file's entry count no longer matches
  the register.
- Lists: CrUX top sites (`build-top-sites-filter.mjs`), Public Suffix List (`update-psl.mjs`), HostList
  (`update-lists.mjs`: HaGeZi DynDNS 60, HaGeZi Hoster 65, Kees1958 Suspicious 50), Brands (new, hand-curated: the
  freshness check verifies every brand website is still in the current CrUX top 1M), and — if DS adopts it — the
  HaGeZi abused-TLD list.
- Licences in `THIRD_PARTY_LICENSES.md`: CrUX = CC BY 4.0 (Google), PSL = MPL 2.0, HaGeZi = GPLv3.

## 6. Process items carried over from the 3P Matrix 4.2.3 audit (Xplainer v10)

- **C39a / derived values:** any number or label the UI shows that also exists as a constant (scores, thresholds,
  provider names) is rendered from the constant; add 3P Matrix's `check-derived-literals.mjs` pattern to DS's suite.
- **No typed numbers outside named constants:** 3P Matrix `check-magic-numbers.mjs` (acorn) — DS already gathers
  scores in `SCORING_CONFIG`; the check makes it enforceable.
- **Upgrade tests start from what the old version stored** (schema number included) — relevant if `Brands.json`
  replaces stored/remote `BrandDomains` data.
- **COMPAT-REMOVE tags** with a target version for every backward-compatibility branch (e.g. DS's legacy
  `quad9:` alias in `evaluateHostReputation`).

## 7. Order of work in DS

1. §0 patches (small, isolated) + tests.
2. §2 brand list + matching rules; run `fp-sweep.mjs`, compare false alarms before/after.
3. §3 top-sites rebuild (rank cut + brand union).
4. §1 new look-alike check, old three removed; scores calibrated with `fp-sweep.mjs`.
5. §4 unknown age.
6. §5 register + freshness step; §6 checks.
Each step: unit tests in `tests/`, `complete-check.mjs` clean, CHANGELOG entry — and the same change in 3P Matrix's
vendored copy in the same session (C22), until both share one module set.
