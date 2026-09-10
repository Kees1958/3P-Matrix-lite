# 3P-Matrix-lite — Changelog

---

## 3.8.4 — 2026-09-10
**Default risky-site locks (Level 4/5) list refreshed**

- `data/constants.js`'s `DEFAULT_RISKY_SITES_LEVEL4` replaced with an
  updated 22-site list: pornhub.com, xhamster.com, xvideos.com, xnxx.com,
  redtube.com, tube8.com, xgroovy.com, xgroovy.tv, youporn.com,
  spankbang.com, porntrex.com, onlyfans.com, theporndude.com, xvideos.es,
  xhamsterlive.com, fpo.xxx, qorno.com, pornpics.com, f95zone.to,
  xhamster19.com, beeg.com, tnaflix.com.
- `DEFAULT_RISKY_SITES_LEVEL5` now contains `eporner.com` (corrected
  spelling of the previous `eponer.com` entry, which looks to have been a
  typo of the same site).
- Fresh-install-only, per this list's own standing contract (see the
  header comment above it in `data/constants.js`): existing installs'
  already-stored `siteRules` are untouched — a user's own lock on any of
  these hosts, at any level, still always wins.
- `spankbang.com`'s `sb-cd.com` allow-exception (`DEFAULT_MATRIX_ALLOW_OVERRIDES`)
  is unchanged.

---

## 3.8.3 — 2026-09-10
**Bug fix: TLD blacklist entries from Generic/World's base list could not be removed**

- `core/tld-engine.js`'s `rebuildBlockedTldList()` always re-merged the
  full Generic/World base list on every rebuild, with no way to subtract
  from it — so removing one of those TLDs from the tag list was silently
  undone the next time the mode recalculated (slider touch, popup
  reopen). The TLD whitelist already had the right pattern for this
  (`excludedTlds`); the blacklist side never got the equivalent.
- Added `excludedBlockedTlds` to state (`data/state-storage.js`),
  mirroring `excludedTlds` exactly. `rebuildBlockedTldList()` now takes
  and honors it; `ui/popup.js`'s remove-tag handler, mode-slider handler,
  and manual re-add handler all updated to match their whitelist-side
  counterparts. Unlike `BASE_TLDS` on the whitelist side, nothing in the
  blacklist's base list is protected from exclusion.

---

## 3.8.2 — 2026-09-10
**Automated check suite extended (5 new checks) and a stale scope comment corrected — no runtime behavior change**

- `tools/complete-check.mjs` grew from 6 to 11 steps: a static DOM
  element-id cross-reference for `ui/popup.js`/`ui/matrix-panel.js`
  against their own HTML (jsdom-based, new `jsdom` devDependency); a
  functional smoke test for `data/state-storage.js` against a mocked
  `chrome.storage.local` (fresh-install defaults, value normalisation,
  save/load round trip, and the shared-siteRules-reference bug its own
  header comment warns about); a DNR rule-ID range collision check for
  `core/rule-builder.js`; a dependency-hygiene check (no bare import
  specifiers, no orphaned devDependencies); and a circular-dependency
  check over the extension's own import graph.
- Corrected a stale claim in `complete-check.mjs`'s own header comment,
  which said this extension "has no DNR-rule-generation build step" —
  `core/rule-builder.js` in fact builds DNR rules across several numbered
  ID ranges; that claim predates this project having a rule-ID collision
  check at all and is now replaced by one.
- No extension source under `core/`, `data/`, `ui/`, `util/`, `content/`,
  or `manifest.json` changed — this release exists only to package the
  extended check suite as its own versioned `*-tools.zip`.

---

## 3.8.1 — 2026-08-09
**Level 3's Active Policy fail-break bullet reworded — names what actually triggers it instead of "sensitive data"**

- `ui/popup.js`'s `getFailBreakBullet()` — level 3's text changed from "when a
  sensitive data entry field is detected" to "when a field marked as
  password, payment or address is detected". The old wording implied the
  extension has some general sense of what's sensitive; detection is
  actually scoped specifically to `type="password"` and the standardized
  `autocomplete` tokens for payment/address/personal-info fields (see
  `content/fail-break.js`) — a site that never sets those never triggers
  this fallback, regardless of how sensitive the field actually is. The new
  wording names the concrete categories instead, without getting into
  attribute-level implementation detail that wouldn't mean anything in a
  popup bullet. Level 2's bullet is unchanged — it genuinely does trigger
  on any field, no attribute-dependent classification involved.

---

## 3.8.0 — 2026-08-09
**New: Fail-Break Protection (levels 2/3 auto-relax to level 1 on form input) and default risky-site locks; removed a dead message type; fixed a shared-reference state bug**

- **Fail-Break Protection (new).** At level 2, typing into ANY form field on
  the active tab relaxes third-party blocking to level 1 for that tab. At
  level 3, this only triggers for a password/payment/address field
  (detected via `type="password"` and the browser's own normalized
  `autocomplete` token — never the field's value). Levels 4/5 never relax,
  and an explicit site lock always wins outright, including the new
  risky-site defaults below. The relaxation lasts until the tab is closed,
  or is immediately cleared if the user moves the slider or locks the site
  themselves.
  - `content/fail-break.js` (new) — a plain (non-ES-module) content script;
    detects the qualifying input, reports it, never reads what was typed.
  - `core/fail-break.js` (new) — installs/clears one `declarativeNetRequest`
    **session** rule per tab (`tabIds`-scoped, priority 3000). Deliberately
    session-scoped, not dynamic: nothing here touches `chrome.storage` or
    the global ruleset every other tab shares.
  - `background.js` — new `FAIL_BREAK`/`CLEAR_FAIL_BREAK` message types and
    the level/lock decision logic; releases the override on tab close too.
  - `manifest.json` — registers the content script (`<all_urls>`,
    `all_frames: true`); no new permission required.
  - `ui/popup.js` — Active Policy now shows a third green bullet at levels
    2 and 3 explaining the mechanism; clears the override on slider move
    or site lock.
  - `privacy.md` (repo root, not packaged) should be updated per the
    "Fail-Break Protection" wording already agreed — the policy no longer
    reads NO page content at all, since this feature inspects field
    type/autocomplete metadata (never values).
- **Default risky-site locks (new).** 14 sites (inporn.com, porn.com,
  boobse.com, spankbang.com, pornone.com, pornhub.com, youporn.com,
  xgroovy.com, tube8.com, redtube.com, xhamster.com, xvideos.com, xnxx.com,
  porntrex.com) now ship pre-locked to level 4, and eponer.com to level 5 —
  `data/constants.js`'s `DEFAULT_RISKY_SITES_LEVEL4`/`LEVEL5`, seeded into
  `DEFAULT_STATE.siteRules` in `data/state-storage.js`. spankbang.com's own
  CDN, `sb-cd.com`, is pre-allowed as third-party (frame + script) via a new
  `DEFAULT_MATRIX_ALLOW_OVERRIDES` default. **Fresh installs only** — since
  `loadState()`'s merge only ever falls back to `DEFAULT_STATE` for keys
  genuinely absent from stored state, existing installs are untouched. Once
  installed, these are ordinary `state.siteRules` entries — if the user
  re-locks one of these hosts at a different level, that overwrites the
  shipped default with no special-casing needed anywhere.
- **Fixed: shared-reference mutation risk in `DEFAULT_STATE`.** Before this
  release, `DEFAULT_STATE.siteRules`/`matrixRules` were always empty `{}`,
  so the codebase's existing `Object.assign({}, DEFAULT_STATE, ...)`
  pattern (a shallow copy, used in 4 places across `background.js` and
  `ui/popup.js`) never mattered — mutating an empty object in place was
  harmless. Now that those fields hold real seeded data, the same pattern
  would let an in-place mutation (locking/unlocking a site) corrupt the
  shared `DEFAULT_STATE` singleton itself. Added `freshState()` in
  `data/state-storage.js`, which deep-copies `siteRules`/`siteRulesOrder`/
  `matrixRules` while preserving normal `Object.assign` override semantics
  for every other field; switched all 4 call sites to use it. No
  behavior-visible change under normal use — verified via a functional
  smoke test that a working-copy mutation never reaches `DEFAULT_STATE`.
- **Removed: `MSG_SET_MATRIX_DOMAIN_RULE` and `setMatrixDomainRule()`.**
  This message type and its handler had no sender anywhere (flagged by
  `tools/complete-check.mjs`'s message-routing check) — deliberately kept
  wired since the 3.x Domain-column redesign was reverted, in case that
  design was ever reinstated. Confirmed via this file's own history that it
  wasn't going to be, and removed outright: `data/message-types.js`,
  `background.js` (router case + import), `core/matrix-rules.js` (the
  function itself), and the stale comment in `ui/matrix-panel.js` that
  pointed at it. Also cleaned up several now-stale present-tense comments
  elsewhere (`data/constants.js`, `core/connection-matrix.js`) that talked
  about the already-retired `core/block-monitor.js` module as if it still
  existed as a live sibling.
- **Refactor: `getApexDomain()` moved to `util/tld-utils.js`.** Was a local
  copy inside `ui/popup.js`; `background.js` now needs the same logic (to
  resolve `content/fail-break.js`'s reported hostname into an apex domain),
  so it's a single shared, pure function now — both callers behave
  identically, verified against the same test cases as before the move.
- **`tools/complete-check.mjs` updated for the new content script.** Scans
  `content/` now; validates `manifest.json`'s new `content_scripts` entry
  in the file cross-reference check; the message-routing check now also
  recognizes a sender that uses a message type's literal string value
  (rather than the imported constant) as valid evidence — needed because
  `content/fail-break.js`, a plain non-module script, cannot `import` from
  `data/message-types.js` and sends `"FAIL_BREAK"` directly. This is a
  general recognition rule, not a one-off special case, so it will also
  cover any future content script needing the same workaround.

---

## 3.7.9 — 2026-08-05
**SITE_RULES_CAP raised 100 → 200; two hardcoded copies of it in ui/popup.js now import the constant instead; Import Allow now shows/touches level-1 locks only — a domain locked at another level (e.g. 4) never appears there and is never touched by Save**

- **`SITE_RULES_CAP`** (max per-site pinned locks, FIFO eviction) **raised
  100 → 200** in `data/state-storage.js`, the single source of truth.
- **Magic-number cleanup**: `ui/popup.js` had two hardcoded `100` literals
  mirroring the FIFO eviction cap (in the regular per-site lock handler
  and in Import Allow's save handler) instead of importing
  `SITE_RULES_CAP` — meaning the real cap lived in three places, two of
  which would silently go stale on any future change. Both now import and
  use `SITE_RULES_CAP` directly; there is exactly one place the cap is
  defined now.
- **Import Allow is level-1-specific.** A domain locked at another level
  (commonly used for privacy-sensitive categories deliberately locked
  stricter than L1) must never surface in this dialog's plain-text list,
  and Save must never normalize it down to level 1 or unlock it for being
  absent from the textarea — either would defeat the point of having
  locked it stricter in the first place. Pre-population now only includes
  domains locked at level 1, and Save's reconciliation only ever considers
  level-1 domains. (This went back and forth during development — an
  earlier build in this same series briefly changed this, then reverted
  it based on a misreading of unrelated history in this file's own past
  changelog entry (3.5.3, which predates and does not reflect this
  decision); confirmed directly, this is the correct, final behavior.)

---

## 3.7.8 — 2026-08-05
**Fixed: stale "Domain column is clickable" documentation; router now a switch statement; added automated pre-release check suite**

Full-extension audit against the updated (V2) programming-principles
standard. No user-visible behavior changed — the whole pass was
documentation, structure, and tooling.

- `ui/matrix-panel.js`, `ui/matrix-panel.html`: corrected stale header/CSS
  comments that still described an old design — a single clickable "Domain"
  allow/block column setting one combined frame+script override
  (`core/matrix-rules.js`'s `setMatrixDomainRule()`). That design was
  superseded by the current independent per-type Script/Frame cells before
  this changelog's history begins; the comments were never updated to match.
  The Domain column has always rendered as plain, non-clickable text in the
  actual code — only the comments were wrong, not the behavior. Corrected to
  describe the real control (`setMatrixRule()`, one call per type), and
  added a pointer at the Domain-column render branch to
  `setMatrixDomainRule()`'s own header comment, which already documents it
  as an intentionally-kept lower-level primitive for a possible future
  combined control, not dead code left by accident.
- `background.js`: message router converted from an `if`-chain to a single
  `switch` statement on `msg.type`, per the standard's C3 (one router, one
  switch). Every branch's logic and `return true` behavior is unchanged —
  structural only.
- `ui/popup.js`: header comment brought in line with the other modules'
  documentation format (C10) — added a description of the page's role and
  its top-level functions. `popup.js` has no external importers, so this is
  a "key functions" summary rather than a literal "public interface" (that
  term is reserved for functions other modules actually call).
- Added `tools/complete-check.mjs` (run via `npm run check`), a lightweight
  automated pre-release suite covering: syntax (`node --check`), ESLint,
  manifest/package JSON validity, a file cross-reference (C20 — every
  manifest path, `<script src>`, and `import` resolves to a real file, and
  every `.js` file is reachable from the manifest), a message-routing
  cross-reference (C20a — every `MSG_*` constant has a router case and a
  real sender, or is in the documented `BROADCAST_ONLY` set with a reader),
  and a manifest/package.json version-sync check. This is the check that
  would have caught the Domain-column documentation drift above being
  reported as a live control when it no longer was — it now runs as a
  standing warning (not a hard failure, since the primitive being unsent is
  a documented, intentional choice) so the next audit doesn't have to
  rediscover it from scratch. Explicitly does NOT include a JSDOM dry-run or
  functional smoke test (see the script's own header comment for why —
  scoped down for this extension's size, not an oversight).
- `package-lock.json`: was stuck at version `3.7.2` (several releases stale,
  predating this changelog's own coverage) despite `package.json` and
  `manifest.json` being correctly bumped each release; `npm install
  --package-lock-only` re-synced it. Now checked implicitly every time `npm
  run check` is run after `npm install`, since the lockfile only drifts when
  `npm install` itself isn't re-run after a version bump — worth running
  `npm install` (not just editing `package.json`) as part of the release
  step from now on.

---

## 3.7.7 — 2026-08-02
**Changed: popup height now content-driven; Active Policy bullets recolored and reordered**

- `ui/popup.html`: replaced the flat `min-height: 600px; overflow-y: hidden`
  on `body` with content-driven sizing — L1/L4/L5 (no TLD panel, since
  `.tab-panel` is `display:none` unless `.active`) no longer carry ~600px of
  dead space, and L2/L3 (TLD blacklist / whitelist panel) simply grow to fit
  instead of being silently capped at a number that was never verified to
  be tall enough. `min-height: 420px` kept only as a first-paint safety
  floor; `overflow-y: auto` added as a guard against clipping if any level's
  content ever exceeds the browser's own popup height cap. Declared once,
  with the reasoning in a comment, per the single-source-of-truth pattern
  used elsewhere in this file.
- Active Policy bullet colors are no longer tied to `var(--accent)` (which
  changes per level — e.g. yellow at L3), so the "allow" bullets were
  actually showing the level's own color, not a fixed green. Now:
  - Two universal ALLOW bullets — fixed green, always first, always in this
    order, whenever a level has anything to report (every level but L1):
    "3P-scripts & frames are allowed on whitelisted domains" (renamed from
    "Whitelisted domains are allowed as 3P") and "Built-in whitelist allows
    payment services, video embeds, CAPTCHA's and important JS-libraries".
  - Each level's own mode-specific bullet (if it has one) comes next,
    colored with that level's own brand color (`LEVELS[].color`, reused —
    never re-declared as a second hex value): L2 blue "Blocks 3P-scripts
    from N risky TLD's", L3 yellow "Allows 3P-scripts & frames from N
    whitelisted TLD's", L4 orange "3P-scripts for URL's with CDN in name
    are allowed". L1 and L5 have no mode-specific bullet.
  - Block bullets ("Third-party frames/scripts are blocked", etc.) always
    come last, always red.
- `ui/popup.js`: replaced the old ad-hoc rendering (a special-cased L2
  block, an `##TLDWHITELIST##` placeholder string for L3, and a
  post-injection after L4's first rule) with one linear 1-2-3 render pass
  (`ALWAYS_ALLOW_TEXTS` → `getLevelModeBullet()` → `lvl.rules`) — single
  place that decides bullet order/color for every level, instead of three
  different mechanisms that happened to produce the right order by
  coincidence of write-order.
- Also removed the now-fully-unused `rule.type === 'info'` render branch and
  its orphaned `.rule-text-info` CSS (no `LEVELS` entry had ever used type
  `'info'`, and nothing else emitted it either) and the no-op `dim` class
  usages (CSS comment already noted `.rule-text.dim` had no visual effect).

---

## 3.7.6 — 2026-08-02
**Removed: raw numeric IP-address block and non-standard-port block**

- `core/rule-builder.js`: deleted `buildBaseSafetyRules()` entirely (DNR
  rules 1003 non-standard-port block and 1005 raw-IP block) and its call
  site in `rulesForLevel()`. These two blocks previously fired at every
  level ≥ 2, independent of the level's own mechanism.
- `data/constants.js`: removed the now-unused `RP_3P` constant (it existed
  only for `buildBaseSafetyRules()`) and its header reference;
  `MATRIX_RESOURCE_TYPES`'s comment updated to no longer reference it.
- `ui/popup.js`: removed the "IP address only connections are blocked" and
  "Non-standard ports blocked (allowed: 80, 443, 8080, 8443)" lines from
  the `LEVELS` policy-text array — the single source of truth for the
  popup's Active Policy panel, so all 4 occurrences (Levels 2–5) were
  removed from one place.
- `README.md`: removed both blocks from Level 2's description. Also
  dropped the pre-existing "third-party connections over plain HTTP"
  mention from that same sentence while there — that block was already
  removed from the code in an earlier version (see the `core/rule-builder.js`
  ID-map comment: "HTTP/WS rules removed"), so the README had been
  inaccurate on that point independently of this change. Flagged to the
  user rather than left silently.
- `privacy.md` was checked and contains no mention of IP-address or port
  blocking — no change needed there.

---

## 3.7.5 — 2026-08-01
**Fixed: LEVEL MODE / INTERNAL WHITELIST cells stayed grey after reverting a script/frame setting**

- Bug: script/frame cells are two independent buttons (Allow / Block), not a
  toggle. If LEVEL MODE was green (no override) and the user clicked Block
  on script, LEVEL MODE correctly greyed out. But clicking Allow again to
  "undo" it stored a *new* explicit "allow" override rather than clearing
  the original one — so LEVEL MODE (and INTERNAL WHITELIST, same root
  cause) stayed grey forever, even though script had visibly gone back to
  its original, non-overridden behavior.
- Fix: `core/rule-classifier.js` gains `wouldBlockDefault()` — the same
  decision cascade as `wouldBlock()`, factored into a shared `_cascadeFromStep3()`
  helper, but with the Matrix-override step deliberately skipped, i.e. "what
  would the level's own mechanism decide with no override at all". Before
  `core/matrix-rules.js`'s `setMatrixRule()` stores a new "allow"/"block"
  override, it now compares the requested action against
  `wouldBlockDefault()`; if they match, the override has become redundant
  and is cleared instead of stored, so the cell reverts to its original
  color. Same guard applied to `setMatrixDomainRule()` (currently unused by
  the UI, kept consistent as a lower-level primitive), per type.
- `setMatrixRule()`/`setMatrixDomainRule()` now take `url` + `activeHost`
  parameters (needed by `wouldBlockDefault()`'s level-4 CDN check and level
  pin resolution). `background.js`'s `MSG_SET_MATRIX_RULE`/
  `MSG_SET_MATRIX_DOMAIN_RULE` handlers resolve these from the tab's live
  Matrix data (`connection-matrix.js`'s `getMatrixData()`), which is why
  `ui/matrix-panel.js` now sends `tabId` along with its rule-change message.

---

## 3.7.4 — 2026-08-01
**Fixed: INTERNAL WHITELIST column now shows at Level 1 too — same layout at every level**

- Removed the `if (level !== 1)` display gate in `buildColumnGroups()` that
  hid the INTERNAL WHITELIST column at L1. The underlying data
  (`entry.internalWhitelist`, computed in `background.js`) was never
  level-gated — a domain's built-in-trusted status doesn't depend on
  protection level — so this was a display-only inconsistency, not a data
  limitation.
- L1 now renders: Domains connected, INTERNAL WHITELIST, LEVEL MODE, then
  the rest — identical column set to L2-5.

---

## 3.7.3 — 2026-08-01
**Removed: the "Filter domains…" search input, at every level (including L1)**

- Deleted the `#filterInput` text box entirely — markup, its `.filter-bar`
  wrapper, and its dedicated CSS (`.filter-bar`, `.filter-input*`) all
  removed from `ui/matrix-panel.html`.
- Deleted its supporting JS in `ui/matrix-panel.js`: the `elFilterInput`
  reference, the `input` event listener, and the `_filterText` state that
  only existed to drive live substring filtering of the domain list.
  `_renderFilteredTable()` is now the simpler `_renderTable()` — it always
  renders every connected domain, since there's no longer a way to narrow
  the list by typing.
- The `#filterNote` line (the "Showing domains allowed by 3P-Matrix-lite…"
  text) is unaffected and unchanged — it was already a separate element
  from the input, not the input's placeholder, so removing the input does
  not touch it.

---

## 3.7.2 — 2026-08-01
**Changed: LEVEL column renamed to "LEVEL MODE"; L3-5 filter note moved off the placeholder so it can wrap**

- LEVEL column header is now the two-line "LEVEL MODE" label, reusing the
  exact same stacked-label mechanism the INTERNAL WHITELIST column already
  uses (`_setLabel()` in `buildHeader()` — no new rendering code added).
  The intro note's "INTERNAL WHITELIST and LEVEL..." line was updated to
  match ("LEVEL MODE") for consistency.
- L1-5 filter note text is no longer split across two different
  mechanisms (input `placeholder` for L1/L2, a separate element for L3-5) —
  that inconsistency was the actual bug (different visible layout per
  level). Now every level uses the exact same `#filterNote` element/CSS
  (reusing the existing `.panel-intro` class as-is), only the text differs:
  L1 "Showing domains allowed by 3P-Matrix-lite"; L2 keeps its existing
  wording; L3-5 as below. The filter input's placeholder is now always the
  plain "Filter domains…" default at every level — never level-specific
  (a native `<input>` placeholder can't wrap to a second line, which is
  why this moved to a real element in the first place).
- New L3-5 wording: "Showing domains allowed by 3P-Matrix-lite, (sub)domains
  needed for 'login with' (e.g. Google) are shown in yellow (and allowed),
  block them manually."
- `setFilterNote()` guards by resetting the note element to empty/hidden
  before applying the level-specific text, so nothing stale can persist if
  it's ever invoked more than once.
- **Fixed:** Show Matrix's single-window guard (`MatrixController._launch()`
  in `ui/popup.js`) had a race — `chrome.tabs.query()` is async, so two
  rapid clicks of "Show Matrix" could both start before either saw the
  other's in-progress window, letting two Matrix windows open at once.
  Added an in-flight guard (`_launchInFlight`, initialised `false`) that's
  set before the query starts and released on every exit path (focus an
  existing window, creation failure, or successful window creation) — a
  second click while one is already in progress is now ignored instead of
  opening a duplicate.

---

## 3.7.1 — 2026-07-29
**Fixed: filter placeholder text corrected to match the actual instruction**

3.7.0 misimplemented the level-dependent filter text as a separate line
below the input, with a decorative yellow swatch element — neither was
asked for. Fixed: the text now directly replaces the filter input's own
`placeholder` attribute (no separate line, no swatch, just the word
"yellow" in plain text), with the exact wording given: "Filtering
domains, (sub)domains needed for 'login with' services are displayed in
yellow, enable them manually when needed." (Level 2 keeps its own
"whitelists are automatically applied..." placeholder; Level 1 keeps the
plain default, since nothing is filtered there at all.)

Also directly verified — via `unzip -p` on the actual shipped 3.7.0
zip, not just the working source — that the LEVEL column label (reported
as still showing "MODE") is correctly "Level" in both the container and
the already-shipped 3.7.0 package. Very likely a stale, un-reloaded
build on the user's end; flagged for a full remove-and-reinstall rather
than assumed to be a code issue, since direct inspection of the shipped
bytes shows no discrepancy.

---

## 3.7.0 — 2026-07-29
**Auth-as-a-service added to the global whitelist; new "signal list" for
"Login with X" domains (real whitelist at Level 2, informational at
3-5); real pre-existing bug found and fixed: Level 2 never actually
enforced its own TLD blacklist for scripts**

Iterated through several design rounds with the user on how to handle
broad, general-purpose Identity/SSO domains (Facebook, GitHub, LinkedIn,
Apple/Microsoft account domains) — global whitelisting felt like too big
a privacy trade-off for these versus narrow-purpose auth infrastructure.
Landed on:

- **5 auth-as-a-service domains** (Auth0, Okta, OneLogin, WorkOS,
  openai.com) added to `BUILTIN_DOMAINS` — a site integrating one of
  these has made a deliberate, narrow-purpose choice, and blocking it
  means login simply doesn't work. 167 total built-in domains now.
- **New `SIGNAL_DOMAINS`** (10 domains: Apple, Facebook, GitHub,
  LinkedIn, Microsoft account domains) — never auto-allowed by default,
  but flagged in the Matrix so the user has better context to make the
  one-click decision themselves, rather than the extension silently
  guessing "was this a real login click."
- **Except at Level 2**: per explicit design (Level 2 is the light-touch
  tier meant to minimize breakage), the signal list functions as a REAL
  whitelist there — `rule-classifier.js`'s `wouldBlock()` gained a new
  decision step (3b, using a new `2200–2399` DNR ID range, previously
  free) checking `isSignalDomainForType()` only when `level === 2`. At
  levels 3-5, signal domains stay purely informational.
- **INTERNAL WHITELIST column gained a 4th state: yellow** — level-aware
  in `background.js`'s enrichment: green/grey at Level 2 (matching its
  real auto-allowed behavior), yellow at 3-5 (informational only). Also
  gained a domain-specific tooltip ("Built-in whitelist: ..." or "Signal
  (not auto-allowed): ...") showing the category, so hovering always
  explains why a domain was trusted or flagged.
- **The filter-bar note is now level-dependent**: Level 2 reads
  "Filtering domains, whitelists are automatically applied to lower
  website breakage." Levels 3-5 read "Filtering domains, (sub)domains
  needed for 'login with' services are displayed in yellow, enable them
  when needed." Nothing shown at Level 1 (nothing is filtered there at
  all).
- **Show Matrix now splits a subdomain into its own row** whenever it has
  its own explicit `BUILTIN_DOMAINS`/`SIGNAL_DOMAINS` entry distinct from
  its parent — not just the earlier "cdn" case. Makes a parent/child
  whitelist collision (like `hcaptcha.com` vs `js.hcaptcha.com`) visible
  directly in the live table, not just in a static report.

**Real, pre-existing bug found and fixed** (flagged directly by the
user): `isTldBlacklisted()` was only ever consulted by `getModeState()`
(for Mode's Level-2 display color) — `wouldBlock()`, the function that
actually decides what gets blocked, never checked it at all. This meant
a script from a TLD-blacklisted domain was being allowed at Level 2, when
the real DNR rule (`buildTldBlacklistRules`, priority 15) would actually
block it — Show Matrix's Script column was showing green for domains
that were really being blocked. Fixed: added decision step 3c, positioned
correctly in the priority cascade (after Matrix override / builtin /
signal-list allows, so those still correctly win over the blacklist).
Verified via 6 direct scenarios, including that override and builtin
allow still correctly beat the blacklist, and that Level 3+'s unrelated
generic script-block mechanism is unaffected.

All new behavior verified end-to-end: type-aware signal allow/block at
Level 2, the priority ordering against overrides/builtin, the
level-dependent Internal Whitelist color and tooltip, the level-dependent
filter-note text across all 5 levels, and the subdomain-splitting for
both a non-listed subdomain (correctly stays merged) and a genuinely
listed parent/child pair (correctly splits).

---

## 3.6.0 — 2026-07-29
**Built-in whitelist is now type-aware (script/frame separated), hand-classified per domain**

`BUILTIN_DOMAINS` restructured from a flat array to an object keyed by
domain, each with its own `{ script, frame }` flags — 162 domains,
hand-classified into three source lists (script-only, frame-only, both)
rather than assumed, since guessing wrong risks silently breaking a
payment flow or CAPTCHA. Iterated twice with the user: an initial
186-domain pass surfaced 10 parent/child collisions (e.g.
`js.stripe.com` restricted to script while `stripe.com` grants both) —
revised down to 163 domains and 2 collisions, then to 162 with one
remaining, confirmed intentional (`hcaptcha.com` is frame-only,
`js.hcaptcha.com` is script-only — reflecting the real, separate
loader-script vs. challenge-frame embed pattern, not an error).

**Real bug found and fixed via direct testing**: `core/rule-classifier.js`'s
domain lookup used to return whichever builtin entry it iterated to
first, with no priority between an exact match and a broader
suffix-matched parent domain — meaning a specific subdomain's own
narrower flags could be silently overridden by a parent's broader ones,
depending on arbitrary object-key iteration order. Fixed: exact matches
now always win first; among multiple suffix matches, the longest (most
specific) wins.

**A separate, real limitation documented rather than silently accepted**:
DNR's `urlFilter` matches by substring, not exact domain, so a broader
parent domain's *actual enforced rule* can still allow more than a
child's own declared classification — even though the Matrix's own
display (fixed via the exact-match priority above) now shows the
correct, specific answer. Confirmed via direct rule-build test: a frame
request to `js.hcaptcha.com` is genuinely allowed by `hcaptcha.com`'s
broader rule in the real browser, even though `js.hcaptcha.com` itself
is script-only. Domain-anchored DNR rules (same approach as the CDN
regex fix) would close this gap if ever needed; not built now, since the
user confirmed this specific case is acceptable.

**New**: `isBuiltinWhitelistedForType()` (type-aware check, used by
`wouldBlock()` for the real allow/block decision) and
`getBuiltinCategory()` (returns e.g. "Payment — core / international" —
powers a new domain-specific tooltip on the INTERNAL WHITELIST column:
"Built-in whitelist: <category>", so hovering always explains *why* a
domain was trusted). `isBuiltinWhitelisted()` (domain-level, any type)
kept unchanged for Mode's grey trigger and the INTERNAL WHITELIST
column's own green/grey state, which intentionally stays a single
column, not split by type.

`core/rule-builder.js`'s `buildBuiltinAllowRules()` now computes each
domain's `resourceTypes` array from its own flags, instead of always
allowing both `script` and `sub_frame` uniformly.

Fixed two `.slice()` calls (in `background.js`'s fresh-install seeding
and `data/state-storage.js`'s re-sync) that would have thrown, since
`BUILTIN_DOMAINS` is no longer an array — replaced with
`Object.assign({}, BUILTIN_DOMAINS)` for an independent clone, verified
via direct test that mutating the clone never affects the original.

Verified end-to-end: exact per-domain `resourceTypes` in real generated
DNR rules (162/162 correct), the classifier priority fix against the
`js.hcaptcha.com`/`hcaptcha.com` case specifically, `wouldBlock()`
producing the correct allow/block per type at Level 5 (the strictest
level), the tooltip rendering the right category text, and the full
existing test suite re-run with no regressions.

---

## 3.5.4 — 2026-07-29
**"MODE" column renamed to "LEVEL" — actually shipped this time**

This rename (column header, its title tooltip, and the intro banner
text) was implemented correctly in the working tree at some point in a
previous round, but never properly logged in this CHANGELOG or re-zipped
afterward — a screenshot showing the shipped 3.5.3 build still displaying
"MODE" caught the discrepancy. Diffed the shipped 3.5.3 zip directly
against the working tree to confirm this was the *only* drift (nothing
else silently unshipped) before packaging this release.

---

## 3.5.3 — 2026-07-29
**Import allow is now a full editor for site locks, not just an add-only list**

Previously the textarea always opened blank, and there was genuinely no
UI anywhere showing what had already been imported/locked
(`renderPinnedList()` was a no-op stub) — confirmed by direct code
inspection after the user's question about it. Iterated to the final
design across a few rounds of clarification:

- Opening Import allow now pre-populates the textarea with **every**
  currently-pinned domain, regardless of which level it's currently
  locked at — not a partial view filtered to level 1 only (an earlier
  draft did that, then was explicitly widened).
- **Saving overwrites every domain shown to level 1** — a domain can
  only ever be at one level in `state.siteRules` (a single value, not a
  set), so this always fully normalizes it. Deliberate design goal,
  stated explicitly by the user: prevent a domain ever being "locked at
  1 here, locked at 5 somewhere else" inconsistently.
- **Saving also removes any domain that was pinned but is no longer
  present in the textarea** — deleting a line and saving now fully
  unlocks that domain, rather than leaving it untouched. The textarea is
  the authoritative full list now, not an add-only queue.
- Save-side dedup: a duplicate line in the pasted/edited text is only
  processed once. Pre-population itself is also defensively deduplicated
  via a `Set`, ordered by `siteRulesOrder`'s existing FIFO insertion
  order.

Verified via direct simulation of the full cycle: pre-population shows
all 3 domains from a mixed-level state; deleting one line and saving
removes that domain entirely from both `siteRules` and `siteRulesOrder`
while normalizing the remaining two to level 1; adding a new domain on
top of an already-edited list still works correctly without disturbing
the others.

---

## 3.5.2 — 2026-07-29
**Bigger/bolder checkmarks; Script/Frame's non-active side is blank now, not grey**

- Observation-column checkmarks (image/media/stylesheet/fetch-xhr/other)
  are bigger (13px → 16px) and bold, per explicit feedback that they
  needed better visibility. The empty-state dash stays regular weight.
- Script/Frame's non-active half no longer shows grey when overridden —
  it's blank now, at every level. The active half's color (green/red)
  already communicates the override clearly enough on its own; the extra
  grey on the other side was unnecessary. Verified: clicking still toggles
  correctly (the underlying override-tracking data is unaffected — only
  the visual treatment changed).

---

## 3.5.1 — 2026-07-29
**Intro banner made more visible; re-confirmed the built-in-whitelist grey trigger**

- Intro banner text is now white and bold (`.panel-intro`), rather than
  the dim muted grey it used before, per explicit feedback that it needed
  better visibility.
- Re-confirmed directly (via `getModeState()`) that `jwpcdn.com` and
  `jwplayer.com` correctly return `overridden: true` at Level 5, which
  maps to Mode showing grey — a reported red-instead-of-grey observation
  traced to testing a build predating 3.4.3's built-in-whitelist-grey fix,
  not a regression in the current code.

---

## 3.5.0 — 2026-07-29
**A "cdn" subdomain now gets its own row, separate from its bare eTLD+1**

Root cause of "why is `taboola.com` green at Level 4": the table groups
connections by eTLD+1, but the Level-4 CDN check evaluates the actual
specific subdomain of whichever request happened to be sampled first for
that row. If Taboola serves some resources from a `cdn.taboola.com`-style
subdomain, that subdomain genuinely IS treated differently by the real
DNR rule than the bare `taboola.com` — Mode was showing green because it
accurately reflected that one sampled request, not because of any bug in
the classifier (confirmed directly: `taboola.com` alone correctly returns
`block` at L4 with no override).

Per explicit preference: rather than merge these into one (sometimes
misleading) row, a subdomain containing "cdn" that differs from its own
eTLD+1 now gets its own separate table row entirely —
`core/connection-matrix.js`'s new `_groupingKeyFor()` (replacing
`_thirdPartyHostFor()`) returns the full subdomain as the grouping key in
that specific case, instead of always collapsing to the eTLD+1. Any
other subdomain without "cdn" in it still groups under the eTLD+1 as
before — this only splits the specific case that was actually
misleading.

Not level-gated (`connection-matrix.js` stays decoupled from
level/state by design) — harmless at other levels too, since it's still
fully accurate, just occasionally more granular than one row per domain.

No changes needed to `rule-classifier.js` — `isBuiltinWhitelisted()`,
`isTldWhitelisted()`, `isTldBlacklisted()` already tolerate being passed
either a bare eTLD+1 or a fuller subdomain (suffix-matching, not exact
equality), so passing `cdn.taboola.com` as `thirdPartyHost` produces
identical, correct results to passing `taboola.com` directly.

Verified: a bare `taboola.com` request and a different non-cdn subdomain
(`trc.taboola.com`) correctly merge into one row; a `cdn.taboola.com`
request correctly splits into its own; a domain where "cdn" is part of
the eTLD+1 itself (`cdn-scripts.net`, no subdomain distinction to make)
correctly stays as one row, not duplicated. Downstream Mode colors
confirmed to differ correctly between the split rows (`taboola.com`
red, `cdn.taboola.com` green) — the whole point of the fix.

---

## 3.4.4 — 2026-07-29
**Reverted 3.4.2's per-level Mode colors — back to universal green/red**

Per explicit follow-up feedback ("bad idea, change back"): Level 2's
blocked frames are red again (not blue), Level 3's TLD-whitelisted
domains are green again (not yellow). `MODE_LEVEL_COLORS` removed
entirely — Mode is back to fixed green (allow) / red (block) / grey
(overridden) at every level, same universal language as SCRIPT/FRAME,
matching 3.4.0's original simplification. The built-in-whitelist grey
trigger from 3.4.3 is unaffected by this reversion and still applies.

---

## 3.4.3 — 2026-07-29
**Mode greys out when the built-in whitelist — not the level's own mechanism — is what's actually deciding a domain**

`getModeState()`'s `overridden` flag now also fires when a domain is on
the built-in whitelist, not just when a script/frame per-type override
exists. Rationale: at Level 3 for example, Mode's yellow/red story is
specifically about the TLD-whitelist mechanism — but if a domain (like
`google.com`, which is built-in whitelisted for reCAPTCHA) is *also*
built-in trusted, that's what's actually deciding its fate, not the TLD
mechanism Mode is trying to explain. Showing plain yellow there would be
misleading about *why* the domain is allowed. Now it greys out, same
"something else took over" signal already used for per-type overrides.

Verified via 4 direct scenarios: a TLD-whitelisted **and** built-in
domain greys out; a TLD-whitelisted-only domain stays yellow; a
neither-whitelisted-nor-built-in domain stays red; a built-in domain
whose TLD *isn't* whitelisted still greys out (built-in wins regardless
of the TLD mechanism's own verdict). Also re-confirmed via a direct DOM
render test that the underlying yellow/red color logic itself has no
bug — a screenshot showing uniform green across most domains at Level 3
was very likely from a build predating 3.4.2's color-per-level fix,
worth confirming after reloading the extension.

---

## 3.4.2 — 2026-07-29
**Mode's per-level color restored (single-column layout kept); robust Matrix window management**

- **Mode's allow/block colors are level-specific again** — a plain
  universal red (from 3.4.0's simplification) made Level 2's blocks
  (e.g. `doubleclick.net`'s blocked frame, or a script blocked via the
  TLD blacklist) indistinguishable from Level 3-5's, when L2 was always
  meant to read as blue. `MODE_LEVEL_COLORS` reintroduces the original
  per-level allow/block hex values, applied to the single Mode column's
  winning state; grey (a script/frame override exists for this domain)
  stays universal, not level-colored — it means "something else decided
  this," not any particular level's own verdict. Verified: `doubleclick.net`
  at L2 now renders blue, not red.
- **Matrix windows are managed properly now** — previously tracked via an
  in-memory `_winId` in `popup.js`, which reset every time the popup
  itself closed and reopened, silently losing track of a still-open
  Matrix window. Replaced with a live `chrome.tabs.query({})` lookup
  (matching this extension's `matrix-panel.html` URL, reading the `tabId`
  param already embedded in it) — robust regardless of popup
  reloads/service worker restarts. Now: opening Matrix for a tab that
  already has one open focuses it; opening it for a *different* tab
  closes the previous one first, so at most one Matrix window ever
  exists at a time. Verified via simulation across all three scenarios
  (nothing open, same-tab already open, different-tab already open).

---

## 3.4.1 — 2026-07-29
**Level 1 Mode fix, button reorder, shorter tooltip**

- **Fixed**: Level 1 Mode now correctly shows green for every domain.
  `getModeState()` previously treated L1 as "not applicable" → empty
  square, on the reasoning that L1 has no DNR rules at all. That was the
  wrong read: L1 genuinely always allows, which is a real, reportable
  answer (green), not "nothing to report." Overrides remain ignored at
  L1, consistent with `wouldBlock()`'s existing L1 behavior elsewhere.
- **Show Matrix button always rightmost** — swapped order with Import
  allow in `popup.html` (previously Show Matrix first, Import allow
  second; now the reverse, so Show Matrix's position stays consistent
  regardless of which button is visible at a given level).
- Shortened the Show Matrix tooltip: "See what 3P this page connects to."

---

## 3.4.0 — 2026-07-29
**Mode simplified to one fixed-color column at every level; panel branding now reflects the actual protection level**

**Mode redesigned again, per explicit feedback** — dropped the
per-level color-coding scheme entirely (green/blue, yellow/red,
orange/red, red-only) in favor of one column, always present at every
level (including L1 now), using the same fixed green/red/grey language
as SCRIPT/FRAME:
- **empty** — level 1 has no rules built at all, so there's genuinely
  nothing to report for any domain
- **green** — the level's own mechanism (TLD blacklist/whitelist, CDN
  match, or block-only at L5) would allow this domain
- **red** — same mechanism would block it
- **grey** — a script or frame override exists for this domain at all
  (either direction, either type) — Mode doesn't try to reconcile which
  specific type the override affects, since it's a single per-domain
  signal now

`getModeState()` simplified accordingly — no longer returns a
level-colored `{allow, block}` pair, just `{applicable, winnerSide,
overridden}`, with `overridden` now checking BOTH script and frame
overrides (previously script-only). Verified against 6 scenarios
including the user's own reported case (a Level-5 domain whose script was
overridden to allow, correctly showing grey rather than red) and the L1
"no rule" case.

`MODE_COLORS` removed entirely from `matrix-panel.js` — no longer
needed once Mode stopped using level-specific colors.

**Panel branding now reflects the actual protection level** — the
"SHOW MATRIX" title, timer, Close button, and filter-input focus ring
were a fixed cyan regardless of level, which was misleading (a Level-5
page showed cyan branding, not red). `matrix-panel.js`'s `init()` now
sets a `--level-color` CSS custom property from the same five level
colors already used elsewhere, and every branding element reads that
instead of a hardcoded cyan.

**Also included**: a small intro-text wording refinement ("per domain
script and/or frame setting") held from the previous round rather than
shipped as its own release.

Verified via jsdom simulation across L1/L2/L5: Mode is confirmed a single
`rowspan="2"` column at every level (previously L1/L5 only), correct
fixed-color classes render for block/grey states, and the branding color
custom property is set correctly per level.

---

## 3.3.1 — 2026-07-29
**UI polish: panel padding/height, bounded tooltips, updated intro text**

- Show Matrix panel: added `18px` horizontal padding around the whole
  panel (header, intro, filter bar, table all inset uniformly); window
  height increased to 1.5x the original (480px → 720px, after briefly
  trying 2x and finding it too tall).
- **Fixed native tooltip clipping** on the Show Matrix / Import allow
  buttons — the native `title` attribute isn't constrained to the popup's
  own 400px bounds and was getting cut off by the browser window's right
  edge. Replaced with a custom bounded tooltip (`.btn-tooltip`) that wraps
  within a 200px max-width and grows leftward from the button's right
  edge, reusing the same visual language as the existing `.lock-tooltip`
  pattern elsewhere in the popup.
- Updated the Show Matrix intro text to explicitly explain the grey
  convention: "click again to undo... When you override them with per
  domain setting, the indicator turns grey."

---

## 3.3.0 — 2026-07-29
**Level-drift bug diagnosed; Domain column dropped; per-type Script/Frame
control restored; new INTERNAL WHITELIST column; Mode simplified**

**Diagnosed a real bug** (confirmed by the user: they'd changed the
protection level from 3 to 5 while Show Matrix stayed open): the panel
reads `_level` once from its launch URL and never updates it, while
`background.js` always classifies against the live, current level on
every poll. Changing levels mid-session leaves the panel's layout/colors
frozen at the old level while the underlying data reflects the new one.
**Not yet fixed in this release** — flagged for a follow-up decision on
whether the panel should re-fetch and re-render live, or close/prompt on
a level change.

**Fixed a real layout bug** found in the same session: the Domain column
(before its removal below) incorrectly collapsed to a single Block-only
column at L5, mirroring Mode's legitimate L5 collapse. That was wrong —
Domain was about user *action*, not the level's default, and a user
should always be able to explicitly allow a domain even at L5. (Verified
via jsdom before the column was removed entirely — see below.)

**Domain column removed entirely, per-type Script/Frame control restored.**
After using the Domain-column design in practice, it obscured too much —
particularly once distinguishing "built-in whitelisted" from "the level's
own mechanism" became necessary (see below), a single combined per-domain
control couldn't cleanly represent both. Reverted to independent,
per-type clickable cells under SCRIPT and FRAME (using
`core/matrix-rules.js`'s `setMatrixRule(domain, type, action, ...)` — the
lower-level primitive that was deliberately kept in place, unused, after
the original per-type-to-Domain simplification, specifically anticipating
this could happen again). `setMatrixDomainRule` and
`MSG_SET_MATRIX_DOMAIN_RULE` remain defined and handled but are no longer
called by the UI.

**New INTERNAL WHITELIST column**, to the left of Mode — shows the
built-in-trust status on its own dedicated signal: green (built-in
whitelisted, no override), grey (built-in whitelisted but a per-type
override exists for it), or blank (not built-in whitelisted). Purely
informational, never clickable. Two-line header label ("INTERNAL" /
"WHITELIST") — `matrix-panel.js`'s `buildHeader()` gained multi-line
label support (a group's `label` can now be an array of strings).

**Mode simplified accordingly** — `getModeState()` no longer factors in
built-in whitelist status at all (that's the new column's job now).
Still factors in overrides, but scoped specifically to the **script**
override (not frame, not a combined domain override) — matching Mode's
original framing as "explains script's per-domain variability." Verified
against the user's own worked example precisely: a level-3,
TLD-whitelisted domain normally shows yellow in Mode's allow column; if
the user then blocks that domain's script specifically, Mode's allow
square turns grey instead — confirmed via 6 direct test scenarios
including the exact contradicting/consistent/frame-only/L1-ignores-all
edge cases.

All changes verified via jsdom simulation across every protection level
(1/2/3/5) before considering this done — header structure (including the
new multi-line label), row cell counts, per-level Script/Frame
clickability gating (L2 allow-only, L3+ both), and a simulated click
producing the correct `SET_MATRIX_RULE` message with domain+type+action.

---

## 3.2.1 — 2026-07-29
**Fix: level-4 "CDN" check matched anywhere in the URL, not just the domain**

Found via the new Mode column making this pre-existing behavior visible
for the first time: `trafficjunky.com` and `googletagmanager.com` showed
orange (CDN-allowed) at level 4 despite neither having "cdn" in their
domain name. Root cause: `isCdnMatch()` checked the whole request URL
(`url.toLowerCase().indexOf("cdn")`), so "cdn" appearing anywhere in a
request's path or query string — nothing to do with the domain itself —
counted as a match. This wasn't just a display bug: the real DNR blocking
rule (`buildCdnAllowRules()`, `urlFilter: "*cdn*"`) used the identical
loose full-URL pattern, so the actual script-allow behavior at level 4
was equally imprecise, not just Mode's coloring of it.

**Two separate fixes, since only one actually touches Chrome's rule engine:**

- **`core/rule-classifier.js`'s `isCdnMatch()`** (used by `wouldBlock()`
  and Mode's coloring) now parses the URL and checks only `.hostname` —
  plain JS, no DNR constraints apply here at all. Verified: `phncdn.com`
  and `example-cdn.net` still match (cdn genuinely in the domain);
  `trafficjunky.com`/`googletagmanager.com` with "cdn" only in the path
  or query no longer match; malformed URLs return `false` rather than
  throwing.

- **`core/rule-builder.js`'s `buildCdnAllowRules()`** (the actual DNR
  rule) needed a different approach — DNR's `urlFilter` has no way to
  scope matching to just the host portion, so this uses `regexFilter`
  instead, with a pattern (`CDN_HOST_REGEX` in `data/constants.js`)
  anchored to match "cdn" only before the first `/` in the URL (i.e.,
  within the host, never the path/query).

  **Flagged directly by the user**: DNR can reject a regex outright as
  "too complex" for its RE2-based matcher, and critically,
  `updateDynamicRules()` applies its whole batch atomically — one invalid
  rule fails the *entire* batch, breaking every level's blocking, not
  just the CDN one. So this regex is never assumed safe: `background.js`
  now calls `chrome.declarativeNetRequest.isRegexSupported()` once (cached
  in `_cdnRegexSupported`, checked only on the first `applyState()` call)
  before `buildRules()` is ever allowed to use it. If unsupported for any
  reason, `buildCdnAllowRules()` gracefully falls back to the old, looser,
  always-valid `urlFilter: "*cdn*"` — degraded precision rather than a
  broken ruleset. Verified via simulation: the check only fires once
  across multiple `applyState()` calls (cached correctly), and rules
  apply successfully whether the regex reports supported or not.

`rule-builder.js` stays free of direct Chrome API calls by design — the
`cdnRegexSupported` boolean is threaded in as a plain parameter
(`buildRules(state, cdnRegexSupported)` → `rulesForLevel(...)` →
`buildCdnAllowRules(...)`), computed once in `background.js` where Chrome
API access already lives.

---

## 3.2.0 — 2026-07-29
**Mode redesigned to be per-domain; visual unification; cookie removed; intro text added**

**Mode is no longer a static per-level legend — it's per-domain now.**
Extracted the individual mechanism checks that `wouldBlock()` was doing
inline into standalone, individually-tested functions in
`rule-classifier.js`: `isBuiltinWhitelisted()`, `isTldWhitelisted()`,
`isTldBlacklisted()`, `isCdnMatch()`, `getEffectiveLevel()`. `wouldBlock()`
is now built from these same helpers, so Mode's coloring and the actual
block/allow decision can never drift into different answers about the
same domain.

New `getModeState(thirdPartyHost, url, state, activeHost)` computes, per
domain, which side (allow/block) "wins" and why — priority order confirmed
directly with the user across several rounds of clarification:
1. **Level 1** — always allow, nothing else applies
2. **Domain-column override** — wins outright; the other side greys out
3. **Built-in whitelist match** — always green allow regardless of level;
   other side greys out (permanently overruled)
4. **The level's own mechanism**: L2 TLD blacklist (script-scoped in the
   real rules — confirmed via direct code inspection that frames block
   unconditionally at L2/L4 regardless of TLD/CDN, so Mode reflects
   script's outcome specifically, matching the user's own framing);
   L3 TLD whitelist (this one genuinely covers both types, since its DNR
   rule uses the full `RP_3P` resource-type scope); L4 CDN match
   (script-scoped, same reasoning as L2); L5 always block. The losing
   side stays plain empty here (nothing overruled it — it just never
   would have happened).

Verified with **13 direct scenario tests** (every level × every priority
interaction, including domain override beating built-in whitelist beating
level mechanism, and L1 correctly ignoring overrides entirely) before
wiring into rendering, then **4 full DOM rendering tests** confirming the
computed states produce the correct square fill/color/grey in the
browser.

**Visual unification** — Mode, Domain, Script, and Frame all use the same
small-rounded-square style now (`.mini-square`), replacing Domain's
circles and Script/Frame's whole-cell fill from 3.1.1. Script/frame keep
their fixed green/red (not level-dependent — Mode already explains the
level's own color scheme); the overruled-grey state also moved from a
whole-cell fill to the same small square, per explicit feedback.

**Cookie column removed entirely** — not just hidden from the UI. The
`onBeforeSendHeaders`/`onHeadersReceived` listeners (and their real,
documented Chrome performance cost from the `extraHeaders` extraInfoSpec)
are gone from `connection-matrix.js`, since nothing displays that signal
anymore. The footnote warning about it is gone too.

**Intro text added**, modeled on uBOL's DDG Tracker Radar panel: "Click a
square in DOMAIN to allow or block that domain (scripts + frames
together); click again to undo. MODE explains this level's default
applied on a domain, not something you click." Drafted, reviewed, and
revised with the user before being wired in, rather than assumed.

---

## 3.1.1 — 2026-07-29
**Show blocks + Domain whitelist retired (migrated); Matrix header/color redesign**

**Removed entirely, with a one-time migration:**
- `core/block-monitor.js`, `ui/monitor-panel.html/.js` deleted — Show blocks
  is redundant now that the Matrix's Domain column can allow *or* block any
  domain directly.
- The Domain whitelist tab/panel removed from `popup.html`/`popup.js` —
  `buildDomainAllowRules()` removed from `rule-builder.js` (freed ID range
  2000–2199), the corresponding step removed from `rule-classifier.js`'s
  `wouldBlock()`, `state.domains` removed from `DEFAULT_STATE`.
- Since the TLD blacklist (L2) and TLD whitelist (L3) tabs were the *only*
  other options a tab-switcher ever needed to switch between, and neither
  level ever showed more than one panel at once anyway, the entire
  clickable tab-bar UI became unnecessary — removed along with it. Each
  level now shows its one relevant panel directly.
- `MonitorController`, all `MSG_*_MONITOR*` message types, the monitor
  confirm dialog, and `LOCAL_KEY_HIDE_WARNING` all removed.

**One-time migration** (`background.js`'s `migrateDomainsToMatrixRules()`,
run on update, guarded by `state.domainsMigratedToMatrix`): any domains a
user had already whitelisted are ported into `state.matrixRules` as an
`{frame:"allow", script:"allow"}` override — same effective behavior,
now expressed through the mechanism that replaced it. Verified via
simulation: fresh migration, idempotency (a later manual change to
"block" survives a second migration attempt rather than being reverted),
the no-domains case, and non-clobbering of any pre-existing override.

**Matrix UI redesign**, per explicit feedback on the 3.1.0 layout:
- **Real two-row grouped headers** — MODE/DOMAIN/SCRIPT/FRAME now render
  as genuine `colspan="2"` super-headers with Allow/Block sub-headers
  below, replacing the earlier single-row abbreviated labels (`M:Allow`,
  `D:Allow`, etc.) that testing had already flagged as ambiguous. Header
  and every row are still built from one shared column model — now a
  two-level *grouped* model (`buildColumnGroups()` + `flattenColumns()`)
  rather than a flat list, verified via jsdom simulation across L1/L2/L3/L5
  showing correct `colspan`/`rowspan` values and matching row/header cell
  counts at every level.
- **Script/frame cells are now whole-cell fills**, not a small dot —
  fixed green (allow) / red (block) regardless of protection level, since
  Mode already explains the level-specific color scheme; these show the
  plain, always-consistent literal outcome instead.
- **Higher-contrast grey for the overruled state** — now fills the whole
  half-cell (`--overruled-grey: #9CA3AF`) rather than a small dot, per
  explicit feedback that the previous treatment wasn't visible enough.
- Mode/Domain columns keep their original small-swatch-dot presentation —
  only script/frame changed, per the specific feedback given.
- Two-row sticky header uses fixed-height rows (24px each) with explicit
  `top: 0` / `top: 24px` offsets, so the two sticky rows stack correctly
  on scroll regardless of content specifics.

Full regression sweep (syntax, ESLint, HTML balance, manifest validity,
C20/C20a message-routing checks) clean throughout.

---

## 3.1.0 — 2026-07-29
**New: Interactive Show Matrix — per-domain allow/block, potentially replacing Show blocks**

Show Matrix gains a clickable "Domain" column pair (Allow/Block) that lets
you override the current protection level's default disposition for any
observed domain — the first real interactivity this feature has had, and
a step toward making Show blocks unnecessary (users can now allow *or
block* any domain directly from the Matrix, not just allow blocked ones
via the separate Show blocks panel).

**Design, as specified and confirmed with the user:**
- **Mode** column (informational only, never clickable) — a per-level
  color legend explaining why cells are colored the way they are:
  L1 green-only, L2 green/blue, L3 yellow/red, L4 orange/red, L5 red-only.
- **Domain** column (the only interactive control) — clicking Allow or
  Block sets ONE override covering both frame and script together, not
  independently. Simpler than the originally-planned per-type controls,
  and means a domain override always affects both at once. L2 only allows
  the Allow-half to be clicked (matching the spec: blocking additional
  domains isn't offered at L2, only un-blocking is new there); L3-5 both
  halves are clickable; L1 has no Domain column at all (nothing is
  blockable there).
- **script/frame columns** are now purely informational, split into
  Allow/Block halves reflecting the domain's current effective
  disposition. When a Domain-column override is active, the half it
  *overruled* shows grey instead of its normal color — visible at a
  glance without needing to check the Domain column.

**New backend, from the ground up:**
- `state.matrixRules` — `{ [domain]: { frame?: "allow"|"block", script?:
  "allow"|"block" } }`, independent from the existing `state.domains`
  domain-wide whitelist.
- `rule-builder.js`'s new `buildMatrixOverrideRules()` — a genuinely new
  rule TIER (not a variant of the existing whitelist): block half at
  priority 2000 (beats every existing allow rule at 1000, including the
  level-4 CDN allow and built-in whitelist), allow half at 1000. Uses the
  already-reserved `4000–4199` ID range.
- `rule-classifier.js`'s `wouldBlock()` now checks `matrixRules` first
  (right after the L1 early-return, before built-in/TLD/CDN logic) — one
  classifier, so Show blocks and the Matrix's own cell coloring can never
  drift into different opinions about the same domain.
- New `core/matrix-rules.js` — `setMatrixDomainRule(domain, action, ...)`,
  the actual entry point the UI uses (sets/clears frame+script together
  atomically); `setMatrixRule(domain, type, action, ...)` kept as the
  lower-level per-type primitive, still exported and handled, in case
  per-type control is wanted again later.
- `connection-matrix.js` gained `sampleUrl` (first-seen URL per domain,
  needed for the level-4 CDN-substring heuristic) and exposes `host` —
  both consumed only by `background.js`'s enrichment step, keeping
  `connection-matrix.js` itself decoupled from `rule-classifier.js`/state,
  per its existing design principle.
- Two new message types: `SET_MATRIX_RULE`, `SET_MATRIX_DOMAIN_RULE`.

**New UI, from the ground up:**
- `matrix-panel.js`'s column set is now generated dynamically per level
  from one shared model (`buildColumnModel()`) — header and every row's
  cells are built from the exact same model, ruling out header/body
  column-count mismatches structurally rather than by careful bookkeeping.
- Column labels use explicit prefixes (`M:Allow`/`D:Allow`/`S:Allow`/
  `F:Allow`, etc.) rather than relying on grouped super-headers, since a
  first draft using bare "Allow"/"Block" repeated across Mode/Domain
  pairs was genuinely ambiguous — caught by testing, not assumed away.
- `popup.js` now passes the effective protection level to the panel URL
  (needed for Mode coloring and per-level interactivity gating).

**Verification approach** (this was a large, multi-file change — every
piece was tested, not just read):
- `rule-classifier.js`: direct calls confirming a matrix block override
  beats a level-4 CDN allow, a matrix allow override beats the level-2
  generic frame block, and L1 ignores overrides entirely.
- `rule-builder.js`: `buildRules()` output inspected across 5 scenarios
  including independent per-type overrides on the same domain.
- `matrix-rules.js`: full lifecycle (set, switch, clear, auto-cleanup of
  empty domain entries) verified via simulation.
- Full backend chain: observed traffic → computed disposition → simulated
  click → override applied → disposition recomputed, verified end-to-end.
- **UI**: a real jsdom simulation of the actual `matrix-panel.js` file
  (not a mock) across L1/L2/L3/L5 — header/row cell counts match at every
  level, L2's block-half is correctly non-clickable while allow-half is,
  clicking sends the correct `SET_MATRIX_DOMAIN_RULE` message, and the
  grey "overruled" CSS class renders exactly where expected on the
  informational script/frame cells.

---

## 3.0.3 — 2026-07-29
**Fix: Show blocks race condition — session appeared expired before it ever started**

Root cause: `getMonitorData()` computed `elapsed` the same way for both
`STARTING` and `RUNNING` phases — `session.timeElapsed + (Date.now() -
session.startTime)`. But `session.startTime` is `null` during `STARTING`
(the clock doesn't truly start until `markMonitorStarted()` fires, on the
reload's navigation actually committing) — `Date.now() - null` coerces to
`Date.now() - 0`, producing a huge "elapsed" value and therefore
`remaining: 0`.

If the monitor panel's very first poll landed in the (entirely plausible)
window between `startMonitor()` registering the listener/triggering the
reload and the reload's navigation actually committing, it would see
`remaining: 0`, render the countdown as already expired ("0:00", red),
and effectively look dead on arrival — reported as "the monitor does not
start."

This is a **race condition**, not a deterministic bug — whether it
manifested depended on how fast the reload's navigation committed
relative to the panel's first poll, so it could easily have appeared to
work in earlier casual testing purely by timing luck. It has been latent
since the phase-enum hardening in v2.5.0, not introduced by this
session's rename work.

**Fix**: `getMonitorData()` now only computes the live elapsed time while
`phase === RUNNING`; `STARTING` and `PAUSED` both report the frozen
`timeElapsed` (0, until the clock actually starts) instead.

Verified via direct simulation of the exact `startMonitor()` →
`markMonitorStarted()` sequence: before the fix, a poll taken between
those two calls returned `elapsed: 1785416156405, remaining: 0`; after
the fix, the same poll correctly returns `elapsed: 0, remaining: 300000`
(the full 5 minutes).

---

## 3.0.2 — 2026-07-29
**Full "Scout" → "Matrix" naming cleanup, domain/request counter, and a live filter box**

**Naming cleanup** — internal identifiers previously kept as "scout" (a
deliberate compromise flagged when Show Matrix was first renamed from
Snoop Scout) are now fully renamed to match the user-facing name:
- Files: `core/connection-scout.js` → `core/connection-matrix.js`,
  `ui/scout-panel.html` → `ui/matrix-panel.html`,
  `ui/scout-panel.js` → `ui/matrix-panel.js`
- Constants: `SCOUT_RESOURCE_TYPES` → `MATRIX_RESOURCE_TYPES`,
  `SCOUT_CAP` → `MATRIX_CAP`, `SCOUT_DURATION` → `MATRIX_DURATION`
- Message types: `MSG_START_SCOUT` → `MSG_START_MATRIX`,
  `MSG_STOP_SCOUT` → `MSG_STOP_MATRIX`,
  `MSG_GET_SCOUT_DATA` → `MSG_GET_MATRIX_DATA`,
  `MSG_SCOUT_CLOSED` → `MSG_MATRIX_CLOSED`
- Functions: `startScout`→`startMatrix`, `stopScout`→`stopMatrix`,
  `getScoutData`→`getMatrixData`,
  `clearScoutOnNavigation`→`clearMatrixOnNavigation`,
  `clearScoutOnTabClosed`→`clearMatrixOnTabClosed`,
  `startScoutWatchdog`→`startMatrixWatchdog`,
  `_scoutListener`→`_matrixListener`
- `ScoutController` → `MatrixController` (popup.js); button id
  `snoopScoutBtn` → `showMatrixBtn` (now matches its own CSS class)

Confirmed no collision with the extension's own "3P-Matrix" branding
before starting — no existing identifier used "matrix" as a name. Full
sweep afterward (syntax, ESLint, HTML balance, manifest validity, C20/
C20a message-routing checks, and an end-to-end functional simulation of
the renamed module) all pass; a project-wide case-insensitive search
confirms zero remaining "scout" references anywhere in the codebase
(CHANGELOG history excepted, since that's a historical record).

**New: live filter box** in the Show Matrix panel — a text input above
the table that filters visible rows by domain substring match, live on
every keystroke (no round-trip to the background script; filtering
happens against the already-fetched entry list client-side). Distinct
empty-state message when the filter matches nothing ("No domains match
...") vs. genuinely no connections observed yet.

**New: domain/request counter** in the panel header ("N domains · M
requests"), reflecting true totals regardless of the filter box above.
`connection-matrix.js` now tracks a `requestCount` per tab bucket,
incremented once per qualifying `_scoutListener` (now `_matrixListener`)
event — deliberately NOT incremented by the cookie-detection listeners,
since those fire on separate stages of a request the main listener may
have already counted, which would have double- or triple-counted the
same underlying request.

**Removed**: the WebRTC data-channel disclaimer line from the panel
footnote (per request, as a tribute to original uMatrix's simplicity).

---

## 3.0.0 — 2026-07-29
**Show Matrix: stylesheet column restored, positioned after media**

Re-added the dedicated `stylesheet` column (folded into "other" as of
2.10.1's exact-uMatrix-match pass), based on a real observed pattern: many
adult sites — which lean heavily on third-party ad-tech/widget
infrastructure rather than mainstream self-hosted advertising — showed
elevated third-party stylesheet traffic. That's a legitimate, visible
signal about how much embedded external infrastructure a page pulls in,
distinct from the CSS-content-inspection concern (NoScript's "Block
CSS-based scanners") that this tool still can't address, since
`webRequest` only sees that a stylesheet request happened, never its
content.

Column order: cookie / image / media / **stylesheet** / script / frame /
fetch-xhr / other. Panel widened 900px → 960px for the 8th column.

Font/object/ping/csp_report/webbundle/websocket remain folded into
"other."

**Version bump to 3.0.0** at the user's explicit request, marking this as
a deliberate milestone rather than continuing the 2.x patch/minor
sequence — no breaking changes accompany this jump; it's a version-number
decision, not a compatibility one.

---

## 2.10.1 — 2026-07-29
**Show Matrix: exact match to original uMatrix's column set + cookie-detection performance note**

- Dropped the dedicated `stylesheet` column — folds back into `other`
  alongside font/object/ping/csp_report/webbundle/websocket. Column set
  now matches original uMatrix exactly: cookie / image / media / script /
  frame / fetch-xhr / other.
- Panel narrowed 960px → 900px for one fewer column.
- Added a footnote line: cookie detection (via `extraHeaders`) has a real
  Chrome-documented performance cost under Manifest V3 — recommends using
  Show Matrix on-demand rather than leaving it running continuously.

---

## 2.10.0 — 2026-07-29
**Added: cookie column (tribute to original uMatrix's column set)**

Unlike every other column, `cookie` is not a `webRequest.ResourceType` —
it's a signal derived from inspecting the `Cookie` (outgoing) and
`Set-Cookie` (incoming) HTTP headers, which requires two additional
listener stages beyond the existing `onBeforeRequest`:

- `onBeforeSendHeaders` — detects an outgoing `Cookie` header (the browser
  sending a previously-stored cookie back to that third party)
- `onHeadersReceived` — detects an incoming `Set-Cookie` header (that
  third party asking the browser to store a new cookie)

Both require the `'extraHeaders'` extraInfoSpec — Chrome hides
Cookie/Set-Cookie from webRequest listeners by default (since Chrome 72)
unless explicitly requested. **Real, documented Chrome performance cost**
to specifying `extraHeaders`; accepted as the tradeoff for having this
signal at all. Neither listener requests `'blocking'`, so this stays
compatible with Manifest V3's restriction on blocking webRequest for
non-policy-installed extensions.

Refactored `_scoutListener`'s third-party-host resolution and
entry-lookup-or-create logic into shared helpers (`_thirdPartyHostFor`,
`_getOrCreateEntry`), since the two new cookie listeners need identical
logic — avoids three copies of the same skip/dedup logic.

Verified via simulation: a script request with no cookie header stays
untagged; a request with an outgoing `Cookie` header gets tagged; a
response with an incoming `Set-Cookie` header gets tagged; a request with
headers present but no cookie-related header stays untagged.

Column order updated to roughly follow original uMatrix's sequence:
cookie / image / media / script / frame / stylesheet / fetch-xhr / other
(stylesheet retained from the earlier round; websocket remains folded
into "other" per the previous decision). Panel widened 890px → 960px for
the 8th column.

---

## 2.9.3 — 2026-07-29
**Show Matrix: websocket folded into "other", media kept — matching original uMatrix's column set**

- Removed the dedicated `websocket` column; it now collapses into `other`
  alongside font/object/ping/csp_report/webbundle.
- Kept `media` as its own column, since original uMatrix had one.
- Table is now 6 type columns: script / frame / image / media /
  stylesheet / fetch-xhr / other (7 including domain).
- Panel window narrowed 960px → 890px for the one fewer column.

---

## 2.9.2 — 2026-07-29
**Fix: webbundle/csp_report were invisible instead of collapsing into "other"**

`SCOUT_RESOURCE_TYPES` didn't include `webbundle` or `csp_report` at all,
so Chrome never delivered those events to the listener in the first
place — they weren't "other," they were invisible. Added both to the
filter and to `_typeLabel()`'s "other" collapse group, alongside
font/object/ping.

**Confirmed `webtransport` is deliberately NOT added**: pulled Chrome's
actual current `webRequest.ResourceType` enum directly from their
documentation — `"webtransport"` is not a member of it (only
`declarativeNetRequest.ResourceType`, a different API, includes it).
Adding a type string to the listener's filter that isn't a real
`webRequest.ResourceType` value risked breaking the listener registration
entirely. WebTransport handshakes (which `webRequest` does document
intercepting, per Chrome's own release notes) most likely already surface
as `"other"` given the enum's actual contents.

Only `stylesheet` gets its own column, per this round's direction — no
separate columns for webbundle/webtransport/csp_report; all fold into
"other" alongside font/object/ping.

---

## 2.9.1 — 2026-07-29
**Show Matrix: added stylesheet column, removed websocket disclaimer**

- `stylesheet` now gets its own table column instead of collapsing into
  "other" — 8 type columns total (script/frame/image/media/stylesheet/
  fetch-xhr/websocket/other). `font`/`object`/`ping` still collapse into
  "other".
- Removed the "Websocket only shows that a connection opened..." sentence
  from the panel footnote. The WebRTC limitation note remains.
- Panel window widened 900px → 960px; column width 58px → 64px to
  comfortably fit the new column.

---

## 2.9.0 — 2026-07-29
**Renamed Snoop Scout → Show Matrix; removed field-heuristics feature;
removed pre-launch confirm dialog; always reloads; full uMatrix-style
resource-type coverage**

After the field-classification heuristics repeatedly failed to detect
fields that were clearly visible on real pages (Ziggo's login form,
notably) — and it became clear the underlying question ("which
third-party connection is *this* field's data actually going to?") wasn't
answerable with the DOM-inventory approach that had been built — that
whole feature direction was abandoned rather than patched further.

**Removed entirely:**
- `core/field-classifier.js`, `core/field-scanner-core.js`,
  `data/field-patterns.js`, and the whole `content/` directory
- The `scripting` permission (no longer needed — no content-script
  injection happens anymore)
- The "Looking at" panel section and its chips
- The pre-launch reload-vs-passive confirm dialog (`scoutConfirmOverlay`
  and its CSS/JS wiring) — no more Cancel/NO-RELOAD/YES-RELOAD choice

**Renamed:** the feature is now **Show Matrix**, not Snoop Scout, in every
user-facing string (button, panel title, tooltip). Internal file/module
names (`scout-panel.*`, `connection-scout.js`, message type names like
`START_SCOUT`) were deliberately **not** renamed, to limit the size of
this change — flagged explicitly rather than done silently.

**Behavior change:** launching Show Matrix now **always reloads** the tab
immediately, matching Show blocks' original behavior — no more passive
("continue without reload") option.

**Expanded resource-type coverage**, matching classic uMatrix's full
matrix view rather than a narrow subset: `SCOUT_RESOURCE_TYPES` now
covers the complete set (script, frame, image, media, stylesheet, font,
object, fetch/xhr, websocket, ping, other) instead of just
script/frame/fetch-xhr/websocket. The panel table gained **image**,
**media**, and **other** columns (stylesheet/font/object/ping collapse
into "other" to keep the table readable) — 7 type columns total. Panel
window widened 700px → 900px to fit them.

No message types, storage keys renamed. `MSG_REPORT_PAGE_FIELDS` removed
(no longer has a producer or consumer).

---

## 2.8.2 — 2026-07-29
**Fix: "No form fields detected" on real login pages (Ziggo)**

A visible email + password login form was reported as having no fields at
all. Two compounding causes, both fixed:

1. **SPA rendering timing.** A single one-shot scan can miss forms that a
   JS framework renders after the page's "load" event fires (common —
   many SPAs ship an empty root `<div>` in the initial HTML). Fixed by
   adding a debounced `MutationObserver` in `content/field-scanner.js`
   that re-scans and re-reports as the DOM changes, instead of scanning
   once and stopping.
2. **Iframe-scoped forms.** The scanner only ever looked at the top-level
   document. `chrome.scripting.executeScript` is now called with
   `{allFrames: true}` — the extension's `<all_urls>` host permission
   allows this to reach cross-origin iframes too, something a page's own
   script could never do under the same-origin policy.

Multi-frame reporting required a structural change: `connection-scout.js`
now stores one field-scan summary **per frame** (`pageFieldsByFrame: Map
<frameId, summary>`, keyed via `chrome.runtime.MessageSender.frameId`)
rather than a single value that the most recent report would silently
overwrite. `getScoutData()` merges all frames' summaries (counts summed,
field lists concatenated) for the popup. Verified via simulation: two
frames reporting independently, one frame re-scanning without clobbering
the other's data, and a full clear on navigation.

**Known remaining limitation:** an iframe that navigates to a new URL
*within itself* (without a full top-level page navigation) won't get a
fresh scanner injection — the navigation hooks only fire for the
top-level frame. The `MutationObserver` still catches same-document DOM
changes within that iframe; only an iframe-internal *navigation* falls
outside current coverage.

---

## 2.8.1 — 2026-07-29
**Fix: field scanner injected too early to see any form fields**

The field-scanner (re-)injection on navigation was hooked to
`webNavigation.onCommitted`, which fires at the very start of a
navigation — before the DOM is built or any page JS has run. Injecting
there meant the scanner almost always scanned an empty document, so
"Looking at" showed nothing regardless of which page was tested.

Moved field-scanner (re-)injection to its own `webNavigation.onCompleted`
listener, which fires once the page has actually finished loading —
`onCommitted` is still used for the monitor timer-start and Scout
entry-clearing, which are correct to do early. The reload path (Scout's
"YES-RELOAD" choice) is affected by this too, since it relied entirely on
the navigation hook to trigger the re-scan after the reload.

The very first scan on a passive ("NO-RELOAD") Scout start was not
affected — it injects immediately against the page's current, already-
loaded DOM at the moment the button is clicked.

---

## 2.8.0 — 2026-07-29
**New: "Looking at" field-classification heuristics**

Snoop Scout's panel now shows a page-level summary of detected form fields,
classified as sensitive (password, card number, CVC, expiry, passport
number) or form (name, email, phone, address, zip, city, company,
username), via a new content-script-based scanner.

New files:
- `data/field-patterns.js` — regex patterns sourced directly from
  Chromium's `autofill_regex_constants.cc.utf8` and Firefox's
  `HeuristicsRegExp.sys.mjs` (real production autofill heuristics, not
  invented). Covers English plus the 7 EU languages both browsers actually
  cover: German, French, Spanish, Italian, Portuguese, Dutch, Polish.
  **Deliberately does not guess translations for the other ~17 EU official
  languages** (Swedish, Danish, Finnish, Greek, Czech, Slovak, Slovenian,
  Croatian, Romanian, Bulgarian, Hungarian, Estonian, Latvian, Lithuanian,
  Maltese, Irish, and others) — a wrong translation of "password" would be
  worse than an honest, visible gap for a feature whose entire point is
  catching sensitive fields. Stated explicitly in the panel's footnote and
  in the file's own header comment.
- `core/field-classifier.js` — pure classifier: structural signals
  (`type="password"`, standards-compliant `autocomplete` tokens) checked
  before any regex, per Chromium's own design principle that input type is
  more reliable across languages than name-based matching. Verified with
  25 test cases spanning every covered language.
- `core/field-scanner-core.js` — pure DOM-scanning logic (no `chrome.*`
  API usage), verified against a synthetic multi-language test form via
  jsdom.
- `content/field-scanner.js` — the actual injectable content script.
  Written as a **classic script** using dynamic `import()` rather than
  static `import`/`export`, since `chrome.scripting.executeScript({files})`
  cannot execute ES modules directly.

**Wiring:** injected on Scout start (immediately for a passive start; via
the existing navigation hook once a reload completes) and re-injected on
every subsequent navigation, but only for tabs actually being Scouted.
Reports back via a new `REPORT_PAGE_FIELDS` message, validated against
`sender.tab.id` (not spoofable by the page itself), stored per-tab in
`connection-scout.js`, and reset on navigation like the rest of that
module's per-page state.

**Scope, stated plainly in the panel:** this is a page-level field
inventory, not yet correlated to which specific third-party domain each
field's data is actually sent to — that harder network-payload correlation
remains future work.

**New permission:** `scripting` (required for on-demand content-script
injection). Not a static, always-on content script — only injected while
Snoop Scout is actively observing a tab, matching this extension's
guard-conscious, init-on-demand design elsewhere.

---

**Removed: Snoop Scout's "This tab" column**

`onThisTab` was hardcoded `true` at the single place an entry is ever
created — `connection-scout.js` tracks one isolated bucket per tab, so
there was no code path where it could ever be anything else. The column
implied a cross-tab "also seen elsewhere" comparison that was never
actually built (and would require a genuinely different, persistent
cross-tab storage model with its own retention/privacy tradeoffs to build
properly — see conversation notes). Removed rather than left showing a
value that was never meaningfully computed. Table is now: domain / script /
frame / fetch-xhr / websocket.

---

## 2.7.2 — 2026-07-29
**Scout confirm dialog: color swap + reload-failure visibility**

- Swapped the confirm dialog's button colors: "Reload & capture all" is now
  yellow, "Continue without reload" is now green.
- `chrome.tabs.reload()` in the `START_SCOUT` handler previously had no
  error checking at all — if it silently failed (restricted page, tab
  closed in the interim, etc.) there was no way to tell. Now checks
  `chrome.runtime.lastError` and logs a `console.warn` on failure, so a
  real failure is visible in the service worker console instead of looking
  identical to a successful no-op. Simulated the handler logic directly
  (mocked `chrome.tabs.reload`) to confirm the call itself fires correctly
  given `reload: true` — the reported "reload doesn't reload" issue could
  not be reproduced at the logic level, so this diagnostic is the next step
  pending confirmation from the actual browser console.

---

## 2.7.1 — 2026-07-29
**Snoop Scout: pre-launch reload-vs-passive confirm dialog + capability footnote**

Snoop Scout was found to miss requests that fired before the panel was
opened (webRequest can't retroactively see traffic it wasn't registered
for), producing a visibly incomplete picture compared to a reload-triggered
monitor like Show blocks. Rather than silently reloading (breaking the
passive-by-default design) or silently staying incomplete, added a confirm
dialog every time Snoop Scout is launched:

- **Cancel** — no action
- **Continue without reload** — today's existing passive behavior, observes from the moment the panel opens
- **Reload & capture all** — reloads the tab (listener is registered first, so nothing between registration and reload is lost) for a complete picture from page-load start

Reuses the existing `.monitor-confirm-*` CSS/markup pattern from the Show
blocks dialog rather than introducing new styling.

**Deliberately not suppressible** — unlike the Show blocks dialog's "hide
this warning" checkbox, this one has no persisted skip. The reload-vs-
passive tradeoff (an in-progress checkout or form submission could be
interrupted by a reload) has real, situational consequences each time,
and passive was chosen as Snoop Scout's *default* specifically so this
decision could be made consciously per use rather than defaulted away.

`background.js`'s `START_SCOUT` handler now accepts a `reload` flag and
calls `chrome.tabs.reload()` only when the user chose that option.

**Capability-limits footnote** — added a small, persistent note at the
bottom of the Scout panel (not a one-time popup) stating that WebSocket
only shows connection-opened, not individual messages, and that WebRTC data
channels aren't visible at all. Chosen over adding this to the confirm
dialog so it doesn't compete for attention with the actual reload decision,
and stays available for reference any time results are being read, not
just at launch.

---

## 2.7.0 — 2026-07-29
**Fix: Snoop Scout no longer filters by block/allow outcome**

Reverted the block/allow classifier filtering added in 2.5.0/2.6.0.
`core/connection-scout.js` no longer imports or calls `wouldBlock()` at all —
Snoop Scout now records every observed script/frame/fetch-xhr/websocket
connection regardless of what our own ruleset would do with it. Show blocks
and Snoop Scout serve genuinely different purposes (the reviewable-blocked
subset vs. full traffic visibility), not the same classification split both
ways, and the earlier filtering was a misreading of that split.

`startScout(tabId, host, cb)` no longer takes a `state` snapshot parameter
(nothing left to classify against) — `background.js`'s `START_SCOUT` handler
simplified accordingly, no longer round-tripping through `loadState()`.

Verified via a mocked-`chrome.webRequest` simulation harness (not just read
through) before and after the fix, which also caught and fixed an unrelated
defensive gap: `_typeLabel()` previously passed an unrecognized resourceType
through unchanged instead of dropping it — harmless in practice today since
Chrome's own `addListener` types filter should prevent it from ever firing,
but now hardened rather than assumed.

**UI polish:**
- All three policy-action buttons (Snoop Scout / Show blocks / Import allow)
  now share one `--level-color` custom property driven by
  `LEVELS[level-1].color` — same color as each other and as the slider/tab-
  underline, instead of three independently hardcoded colors.
- Snoop Scout column header "On this tab" → "This tab", with `white-space:
  nowrap` applied to all column headers so labels never wrap across lines.
- Snoop Scout button tooltip updated to "See what third-party this page is
  connecting to."

---

## 2.6.0 — 2026-07-29
**Snoop Scout: countdown timer + column label fix**

Added a 5-minute countdown to Snoop Scout, matching Show blocks' timer in
both duration and belt-and-suspenders structure:
- `SCOUT_DURATION` constant (`data/constants.js`), independent from
  `MONITOR_DURATION` so the two features can diverge later without coupling.
- `core/connection-scout.js`: each tab bucket now carries its own
  `startTime`/`timeoutHandle`; the panel auto-closes and notifies via the
  already-wired `MSG_SCOUT_CLOSED` broadcast (reason `"timeout"`) when the
  5 minutes elapse.
- `startScoutWatchdog()` added as the same fallback-interval pattern as
  `block-monitor.js`'s `startWatchdog()`, started once at SW boot.
- `ui/scout-panel.js`/`.html`: countdown clock in the header, ported from
  `monitor-panel.js`'s `startClock`/`formatClock` (yellow at 1 minute
  remaining, red + "■" on expiry).

**Fix: "On this tab" column** — renamed to "This tab" and given a fixed
width + `white-space: nowrap` (applied to all column headers, not just this
one) so it reliably renders on a single line instead of wrapping across
up to three.

---

## 2.5.0 — 2026-07-29
**New: Snoop Scout — passive allowed-connections observer**

Adds a second, always-visible panel button ("Snoop Scout") next to Show blocks /
Import allow in the Active policy row. Where Show blocks reports third-party
requests our own ruleset **would block**, Snoop Scout reports the ones it
**would allow** — script, frame, fetch/xhr, and websocket connections — for the
active tab, in a live table (domain / on-this-tab / per-type checkmarks).

Both features now share one classifier: the block/allow decision logic
(`_wouldWeBlock`/`wouldBlock`) was extracted out of `core/block-monitor.js` into
a new `core/rule-classifier.js`, so "blocked" and "allowed" can never silently
drift into two different opinions about the same request.

New files: `core/rule-classifier.js`, `core/connection-scout.js`,
`ui/scout-panel.html`, `ui/scout-panel.js`.
New message types: `START_SCOUT`, `STOP_SCOUT`, `GET_SCOUT_DATA`, `SCOUT_CLOSED`.
New constants: `SCOUT_RESOURCE_TYPES`, `SCOUT_CAP` (`data/constants.js`).
`manifest.json`: added `ui/scout-panel.html` to `web_accessible_resources`.

Snoop Scout has no pause/resume/timer — it tracks a tab for as long as its
panel stays open, and releases that tab's memory the moment the panel closes
or the tab does (guarded via `tabs.onRemoved` and `webNavigation.onCommitted`
in `background.js`).

*Known limitation, unchanged for this release:* `chrome.webRequest` only sees
the WebSocket handshake, not individual messages sent after the socket opens,
and cannot see WebRTC data channels at all. The websocket column reflects
"a connection was opened," not per-message traffic.

---

**Hardening: `core/block-monitor.js` session state → explicit phase enum**

Replaced the `activeSession` (null-or-object) + separate `.paused` boolean
shape with a single `session` state vector gated by an explicit `phase` enum
(`idle` / `starting` / `running` / `paused`) and a `_assertPhase()` guard
checked at the top of every transition function. An out-of-order call (e.g.
`resumeMonitor()` with no paused session) now logs a warning and safely
no-ops instead of silently acting on stale/undefined state.

Ported from a more hardened sibling implementation of this same module found
in a related codebase — that file explicitly documents mirroring *this*
module's original `sessionTimeoutHandle`/`watchdogHandle` design, so this is
a return port of its own structural improvement, not a new design. Its
separate Privacy Inspector feature's `chrome.storage.session`-based
persistence-across-SW-restart guard was deliberately **not** ported: that
guard exists there because its capture mechanism is a persistent
content-script probe that keeps firing after a service-worker restart,
whereas this module's `chrome.webRequest` listener does not survive a
restart at all — listener and session die together, so there is no
orphaned-event case to guard against here. Revisit this decision if either
`block-monitor.js` or `connection-scout.js` ever moves to a persistent-probe
capture model.

*Two real (and correct) behavior changes fall out of this restructuring —
noted explicitly per project convention, not silent:*
- **Pause now actually freezes the countdown.** Previously `pauseMonitor()`
  accumulated elapsed time into `timeElapsed` but never cleared the primary
  timer, so the 5-minute force-close kept ticking in the background while
  paused; `resumeMonitor()` also never re-armed it. A user who paused to
  review blocked domains could get force-closed moments after resuming even
  if they'd only been reviewing for a minute. The timer is now cleared on
  pause and re-armed for the *remaining* duration on resume.
- **The watchdog no longer double-counts elapsed time for a paused session.**
  It previously read `activeSession.startTime`, which pause left stale (never
  reset), and added `Date.now() - <stale startTime>` on top of the
  already-accumulated `timeElapsed` — inflating the apparent elapsed time the
  longer a session stayed paused, and risking an incorrect `timeout` cleanup
  of a session the user was actively reviewing. The watchdog now only
  evaluates elapsed time while `phase === "running"`.

No message types, storage keys, or public function signatures changed —
`startMonitor`/`stopMonitor`/`pauseMonitor`/`resumeMonitor`/`getMonitorData`/
`allowMonitorDomain`/`startWatchdog`/`markMonitorStarted` keep their existing
names and call contracts; `ui/monitor-panel.js` required no changes.

---

## 2.4.0 — 2026-07-27
**New: Identity/SSO whitelist category (built-in domains)**

Added a dedicated "Identity / SSO" section to `BUILTIN_DOMAINS` in
`data/constants.js`, applied at Levels 2–5 like the existing payment/video/CAPTCHA
categories. Covers Google, Microsoft, Apple, Facebook, GitHub and LinkedIn identity
domains, plus common auth-as-a-service platforms (Auth0, Okta, OneLogin, WorkOS) and
`openai.com` itself.

*Why:* third-party "Sign in with X" flows frequently rely on a hidden or interactive
iframe (silent session check, OIDC token relay, account picker) served from the
identity provider's domain. Previously only `google.com`/`googleapis.com`/`gstatic.com`
were covered (filed under CAPTCHA, not identity) and every other provider was
unlisted — so at Level 2 (which blocks all third-party frames outside the built-in
whitelist) a fresh sign-in could fail while an already-established session on the
provider's own site did not need that iframe and worked fine. This matches a reported
case: Google-account sign-in into a third-party site failed cold at Level 2 but
succeeded once already logged into the Google account directly.

No rule-engine or schema changes — this is purely additional entries in the existing
built-in-domain list, applied through the existing `buildBuiltinAllowRules()` path.
Existing installs will pick up the new entries automatically only on **fresh
install**; users who installed a prior version keep whatever `builtinDomains` list
was seeded into their `chrome.storage.local` at that time (see `loadState()` in
`data/state-storage.js` — the seed only fires when `builtinDomains` is `null`/
`undefined`). Existing users should remove the extension's storage or add the
missing domains manually via the popup's domain whitelist to pick up this change.

---

## 2.3.0 — 2026-07-24
**`var` → `let`/`const` modernization complete (no behavior changes)**

Finished converting the remaining, higher-risk files: `background.js`,
`core/block-monitor.js`, `ui/monitor-panel.js`, and `ui/popup.js` (146 occurrences —
the largest file). The codebase is now 100% `var`-free, and `.eslintrc.json` enables
`no-var` and `prefer-const` permanently (previously excluded while this work was in
progress).

`background.js` and `core/block-monitor.js` were converted manually, checking every
variable individually for real reassignment (module-scope session state like
`activeSession`, `monitorEntries`, `_sessionTimer` — which genuinely get reassigned
through the session lifecycle — correctly became `let`; everything else became
`const`). Both were desk-tested afterward: `background.js` by dispatching all 11
message types through its listener and confirming identical responses;
`core/block-monitor.js` with a dedicated test covering the full session lifecycle
(start → block detection with builtin/user whitelist checks and dedup → pause →
resume → stop), all 15 assertions passing.

`ui/monitor-panel.js` and `ui/popup.js` were converted using ESLint's own scope
analysis (`no-var`/`prefer-const` with `--fix`) rather than manual regex — at this
scale, real JS scope analysis is more reliable than pattern matching. Both were
checked for closures inside `for`-loops before running the fix (none of the 6 raw
loops across these two files capture their loop counter in an async callback, so
`var`→`let` cannot change behavior here) — `ui/popup.js`'s domain/TLD tag list
already used a manual IIFE workaround for the classic loop-closure bug, which is left
in place unchanged. Both files were then desk-tested in a simulated browser
environment (jsdom + a stubbed `chrome` API): `monitor-panel.js` for polling, table
rendering, and pause/resume; `popup.js` for tick rendering, level-based rule-list
rendering at two different levels, and tag removal via the IIFE-wrapped loop — all
assertions passing with zero runtime errors.

---

## 2.2.1 — 2026-07-24
**`var` → `let`/`const` modernization (steps 1–3 of a staged plan; no behavior changes)**

Converted `var` to `let`/`const` in the lower-risk files first — those with no
`for`-loop closures, where `var` vs `let` genuinely cannot change behavior. Every
conversion was checked individually against actual reassignment before choosing
`const` (never reassigned) vs `let` (reassigned) — this was not a blanket
find-and-replace. Two real reassignment patterns were caught and correctly kept as
`let`: `rules` in `core/rule-builder.js` (`rules = rules.concat(...)`, used to build
up a rule array from several sub-builders) and `base`/`merged` in
`core/tld-engine.js`'s TLD-list functions (conditionally reassigned per mode).

Files fully converted: `data/message-types.js`, `data/constants.js`,
`data/state-storage.js`, `util/tld-utils.js`, `core/rule-builder.js`,
`core/tld-engine.js`, `core/site-rules.js`.

`core/site-rules.js` was additionally verified with a dedicated desk test
(add/update/remove/FIFO-eviction-at-cap/empty-state scenarios) — all passed
identically to the pre-conversion behavior.

Remaining `var` usage — `background.js`, `core/block-monitor.js`,
`ui/monitor-panel.js`, `ui/popup.js` — involves real `for`-loops and closures where
`var`→`let` conversion can change behavior (usually by fixing a latent bug) and
needs case-by-case verification; deferred to a later pass. `.eslintrc.json` still
intentionally omits `no-var` until that work is done.

---

## 2.2.0 — 2026-07-24
**ESLint added; ES module migration; real bugs fixed; new feature**

*ES module migration*
- The whole codebase now uses real `import`/`export` instead of `importScripts`/`<script>`
  load order and an implicit shared global scope. The service worker loads with
  `"type": "module"`, and both UI pages load their controller as a single
  `<script type="module">`. Each file now imports exactly what it uses directly.
- Internal `var` usage inside function bodies was deliberately left untouched — this
  codebase uses `var` pervasively (not just at module boundaries, unlike a previous
  ESLint pass on a different extension), so a blanket `var` → `let`/`const` rewrite
  was treated as a separate decision, not bundled into this migration. `.eslintrc.json`
  intentionally omits `no-var` for now.
- `.eslintrc.json` added (`eslint:recommended`, `sourceType: "module"`) — resolves
  cross-file references natively; no manually-maintained globals list needed.

*Fixed: `DEFAULT_STATE` duplication removed for good*
- `ui/popup.js` kept its own literal copy of `DEFAULT_STATE`, separate from
  `data/state-storage.js`'s copy — the exact duplication that caused the divergence
  fixed manually in 2.1.2. Verified before removing it: both copies were currently
  identical, and `state-storage.js`'s copy is only ever read by its own
  `loadState`/`saveState`, which `popup.js` never calls (it talks to the service
  worker via messages instead) — so nothing depended on which copy was in scope.
  `popup.js` now imports `DEFAULT_STATE` from `state-storage.js`; the "must stay in
  sync" comment and the manual-sync risk it warned about are both gone.

*Fixed: `domainTags` undefined-variable bug*
- `ui/popup.js`'s domain-rows-select handler referenced a bare `domainTags`
  identifier that was never declared anywhere — the actual element has
  `id="domain-tags"`. Fixed by caching the real element reference.

*Fixed: domain pagination reset bug*
- `renderDomainTags()` always re-rendered at page 0 after adding/removing a domain
  tag, instead of preserving the current page like the equivalent TLD code does with
  `tldPage`. The `domainPage` variable was being tracked correctly but never actually
  consulted. Now uses `domainPage`, matching the TLD behavior.

*Fixed: `ns` redeclared in background.js*
- Two separate `var ns` declarations in the same function scope (different `if`
  branches for `MSG_SET_STATE` and `MSG_RESUME_MONITOR`). Harmless at runtime — the
  branches are mutually exclusive — but a real `no-redeclare` violation. Both are now
  `const`, scoped to their own block.

*Fixed: `no-prototype-builtins` (8 occurrences)*
- Direct `.hasOwnProperty()` calls in `core/site-rules.js` and `ui/popup.js` replaced
  with `Object.prototype.hasOwnProperty.call(...)`.

*Cleaned up: dead state removed*
- `ui/monitor-panel.js`: `_knownEntries` (written on every poll, never read — the
  actual refresh-comparison logic uses `_lastCount` instead) and `_currentState`
  (declared, never assigned or read) removed.
- Two empty blocks (an intentional `lastError` swallow in `core/block-monitor.js`,
  an intentional URL-parse `catch` in `ui/popup.js`) documented with clarifying
  comments rather than left bare.

*New: duplicate monitor-window prevention*
- The "Show Blocks" button had no click-guard — clicking it more than once while the
  popup stayed open (there was no cooldown or disabled state) opened a new monitor
  window every time. `_winId` was already being tracked for exactly this purpose but
  was never actually checked before creating a new window (a real, unused-variable
  bug caught by ESLint). Fixed: `_launch()` now focuses the existing monitor window
  if one is already open, and only creates a new one if none exists or the tracked
  window was closed independently (detected via `chrome.runtime.lastError`, which
  clears the stale id and creates a fresh window).

---

## 2.1.2 — 2026-07-15
**Code quality — no behaviour changes**

*Duplicated constants removed*
- `EU_LANGS` was defined in three places (`util/tld-utils.js`, `core/tld-engine.js`, and implicitly via `tld-utils.js`). Moved to `data/constants.js` as the single source of truth. `util/tld-utils.js` and `core/tld-engine.js` now reference it from there.
- `MULTI_PART_SUFFIXES` was defined twice verbatim (in `core/block-monitor.js` as an inline local `MULTI` array, and in `ui/popup.js`). Moved to `data/constants.js`. Both files now reference the shared constant.
- `LEVEL_COLORS` in `ui/popup.js` duplicated the colour values already stored in `LEVELS[].color`. Removed `LEVEL_COLORS`; the one call site now uses `LEVELS[pinnedLevel - 1].color` directly.

*DEFAULT_STATE divergence fixed*
- `ui/popup.js` and `data/state-storage.js` each held a copy of `DEFAULT_STATE` that had diverged: `state-storage.js` had `showBlockedCount` that `popup.js` was missing; `popup.js` had `blockedTldDropdownOpen` that `state-storage.js` was missing. Both copies are now fully in sync. A warning comment has been added to `popup.js` requiring any future key addition to be mirrored in both files.

*Storage key constants*
- The raw string literals `"monitorHideWarning"`, `"sessionLevel"` and `"prevSessionLevel"` were scattered as repeated raw strings across `ui/popup.js` and `ui/monitor-panel.js`. Named constants `LOCAL_KEY_HIDE_WARNING`, `SESSION_KEY_LEVEL` and `SESSION_KEY_PREV_LEVEL` are now declared in `data/state-storage.js` and used everywhere.

*Double message send fixed*
- The Import Allow save handler in `ui/popup.js` was firing `MSG_SET_STATE` twice for the same state object (once with a callback, once fire-and-forget). The redundant second send has been removed.

*Silent catch blocks documented*
- All `catch(e) {}` blocks in `background.js`, `core/block-monitor.js` and `ui/monitor-panel.js` now carry an explanatory comment confirming they are intentional and describing why the error is safely ignored.

*CSS tokens*
- `--radius: 6px` and `--radius-sm: 4px` added to `:root` in `ui/popup.html` to match `ui/monitor-panel.html`. Raw `6px` values in `popup.html` now have a matching variable (consumers will be migrated in a future pass).
- Dead CSS rule `.rule-text.dim` removed from `ui/popup.html` — it was identical to `.rule-text` and had no visual effect.

*Stale files removed*
- `logger.html` and `logger.js` removed from extension root — they were legacy artefacts unreferenced by the manifest or any other file.
- Root-level `popup.html` and `popup.js` removed — superseded by `ui/popup.html` and `ui/popup.js` since v2.0; the manifest correctly points to `ui/`.

*_seenDomains bound documented*
- Added a comment to `_seenDomains` in `core/block-monitor.js` explaining its implicit size bound (capped indirectly by `MONITOR_CAP` and `_wouldWeBlock()` filtering; cleared on start/resume).

---

## 1.6.2 — 2025
**Bug fixes**
- Added `tabs` permission to manifest — without it, `chrome.tabs.query` silently returned nothing in the Chrome Web Store version, breaking popup initialisation entirely (slider, lock button, logger all non-functional). Developer mode was permissive and hid the bug.
- Removed `tabs` permission again in favour of routing all `tab.url` reads through the background service worker, which can read tab URLs via `<all_urls>` host_permissions without needing the explicit `tabs` permission. This avoids a prior store rejection where a reviewer found the `tabs` permission unnecessary.
- Fixed stale logs from a previous session appearing in a new logger session. When a prior session was still marked active in storage, clicking SHOW LOGS re-opened the logger without clearing old entries. Now every click always resets `logs`, `logHost` and `logStartTime` before opening the logger tab.
- Fixed `RULE_NAMES` TLD-block index: previously used `GENERIC_BLOCKED_TLDS.concat(WORLD_BLOCKED_TLDS)` to map rule IDs 3200+, but since WORLD already contains all GENERIC entries the concat double-counted them, misassigning rule names from ID 3236 onward. Now uses `WORLD_BLOCKED_TLDS` only (the superset).
- Fixed potential stale-log persistence across SW restarts: `logging: false` and `logs: []` are now written atomically in a single `chrome.storage.local.set()` call instead of two separate calls with a 3-second delay between them. A SW eviction between the two writes could previously leave stale logs in storage.

**Architecture**
- Added `GET_ACTIVE_TAB_INFO` and `RELOAD_ACTIVE_TAB` message handlers to background.js so popup.js and logger.js never call `chrome.tabs.query` directly.

---

## 1.6.1 — 2025
**Features**
- Logger now filters to only show traffic from the 1P domain that was active when SHOW LOGS was clicked. Previously all tabs' traffic was captured indiscriminately.
- Logger header now shows the logged domain name (passed as a URL parameter from the popup, avoiding storage/timing races).
- Removed the "Show blocked domains panel" checkbox (leftover from v2.0 blocked-panel experiment).

**Known limitation**
- `tabs` permission was missing from manifest, breaking the store version entirely (see 1.6.2).

---

## 1.6.0 — 2025
**Features**
- Level 3 (Easy medium mode) now allows both 3P scripts **and** 3P frames from whitelisted TLDs, not just scripts. Bullet text updated to reflect this.
- Removed the explanatory "(covers 95% of traffic...)" info line from the L3 Active Policy panel.

---

## 1.5.0 — 2025
**Features**
- Logger: added **Allow** column at levels 4 and 5. Blocked 3P-script rows get an Allow button that whitelists the script's own domain (extracted from the request URL, not the 1P calling domain) and immediately reloads the source tab.
- Logger: Allow column appears between the Action and Reason columns.
- Logger: domain header pill shows which 1P domain is being logged.

**Bug fixes**
- Allow button previously added the 1P calling domain instead of the 3P script domain. Fixed by extracting hostname from `e.url` rather than using `e.domain`.

---

## 1.4.0 — 2025
**Features**
- Request logger with 5-minute session countdown.
- Logger captures all allowed and blocked third-party traffic matching the extension's rules via `onRuleMatchedDebug`.
- Visibility-only catch-all allow rule (ID 3500) added so XHR/image/font/etc traffic is visible in the logger even though it is never blocked.
- SHOW LOGS button with active/pulsing state.

**Architecture**
- `declarativeNetRequestFeedback` permission added to support `onRuleMatchedDebug`.
- `LOG_TIMEOUT_MS` = 5 minutes, `MAX_LOGS` = 500 (FIFO eviction).
- SW restart recovery: reconstructs remaining log timeout from stored `logStartTime`.

---

## 1.3.x and earlier
- Core DNR rule engine with 5 levels.
- TLD whitelist (L3), domain whitelist (L4/L5), CDN allow (L4), built-in payment/video/CAPTCHA whitelist (L2–L4).
- Per-site lock rules with FIFO cap of 100 entries.
- Toolbar badge showing per-tab blocked request count via `displayActionCountAsBadgeText`.
- Auto TLD detection from browser language settings (BROWSER / CONTINENT / WORLDWIDE modes).
- TLD blacklist for L2 (NONE / USER / GENERIC / WORLD modes).
