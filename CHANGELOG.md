# 3P Matrix — content firewall — changelog

(Started with 4.5.4: earlier docs packages carried no CHANGELOG.md. Technical detail for 4.5.4 is in
PERF_4.5.3_chrome_engine_and_proposals.md section 6 and the principles doc, v13.)

## 5.0.8
- **Fixed: a scam page could trap you in fullscreen again.** 3P Matrix refuses to let a page force fullscreen after you left it — but a page could hide the "you left fullscreen" signal, so the block never kicked in. That signal can no longer be hidden.

## 5.0.7
- **Fixed: 3P Matrix was listed as the cause of other sites' errors.** At levels 4–5, when a site's own request failed (often one 3P Matrix had blocked) and the site ignored the failure, the browser's extension error page showed "Failed to fetch" under 3P Matrix. Those failures belong to the site again and no longer appear there. Blocking works exactly as before.
- **Fixed: a scam page could hide the ClickFix and payment-skimmer warnings.** A page could stop the signal that opens the red warning page, so the warning never appeared (for the skimmer check, which only warns, that switched the protection off). Both warnings now always open.
- **Settings and allow-list files larger than 8 MB are refused** before they are read, with a clear message. Real files are far smaller.
- When 3P Matrix refuses a message, its log now names only the site, never the full page address.
- The extension package no longer includes developer notes (they moved to the project documentation).
- More automatic checks behind the scenes: protection numbering, permissions, and imported files tested with thousands of unusual inputs.

## 5.0.6
- **Protection 9 no longer covers coveryourtracks.eff.org** (the EFF's browser-fingerprinting test page). It is not a risky (adult) site; being on that list also made it count as a "high-risk site" for the protections that tighten there.
- **"Warn about a fake sign-in window drawn on a page" is now protection 18** (was 30), so all "on every site" protections run 1–18 without a gap. Protections 18–29 became 19–30. Your ticks carry over.
- **The fake sign-in window warning (protection 18) now opens the full red warning page** instead of a box drawn on the page — a phishing page could remove that box. Same buttons as the other scam warnings: Go back, Continue once, Trust this site.
- **Security hardening** (after reviewing the uBlock Origin picker flaw; 3P Matrix was not exposed to that flaw itself): the scripts 3P Matrix runs inside web pages can now only send the four messages they need — never change settings, import, reset or trust a site; the password-form and fake-window checks now see the event before a page can stop it; the extension's own pages refuse plug-ins, forms and page-address tricks.
- Programming principles updated with these lessons (messages per sender kind, in-page warnings, JSON messaging, page CSP).

## 5.0.5
- **Blocks now also hold inside background workers.** A page can start a "worker" (a background helper) — for example to run a cryptominer — and the WebSocket and WebAssembly blocks of levels 4–5 only worked in the page itself, not in its workers. Protections 31 (WebSocket), 32 (WebTransport) and 33 (WebAssembly) now also work as network rules (and 31 also via the worker's own script), so they hold in dedicated and shared workers too.
- **New protection 28 (level 3): "Block 3P WebAssembly from dubious or non-safer-region hosts".** Blocks WebAssembly (`.wasm`) that a page or its workers load from a dubious host (suspicious hosting, abused TLDs) on any TLD, or from outside your safer regions. WebAssembly from ordinary safer-region hosts keeps working. Protections 28–32 became 29–33.
- **Protection 10** (abused TLDs) now also blocks WebSocket and WebTransport connections to those TLDs at levels 2–3 (levels 4–5 block every third-party one anyway).
- Known limit (Chrome): a *shared* worker's WebSocket is not visible to extensions, so protection 10's WebSocket part cannot reach it. Level 4–5's protection 31 does reach it.

## 5.0.4
- **Fixed: closing a cookie banner sent you to the previous site or a new tab.** Some sites (e.g. euroingro.com) add a history entry for their cookie dialog and remove it again with a step back when you click Accept or Reject. Protection 3's back-button-trap rule took that step for *your* Back press and skipped past the page. Now only your own Back press (browser button or gesture — the browser marks it, a page cannot fake it) skips a page's added entries; a page stepping back itself just removes its own entries. Scam pages that pile up history entries are still escaped with one Back press.
- **Small warning signs now add up when they are all we have, from a dubious source** (shared with DownloadSentinel 3.5.6). A sign weaker than −15 (e.g. "file served via a script or parameter") now counts — with the usual decay — when VirusTotal does not know the file AND the source is dubious: a host on the misused-for-malware, file-sharing, campaign or host-threat list, an abused TLD, a very young domain or a DNS threat hit. When VirusTotal knows the file, nothing changes. The site check follows the same rule (a site visit never has a VirusTotal answer). Real case: a hidden `.bin` from a Google Drive link now reaches the warning line.
- **Protection levels renamed:** 1 Off (allow all), 2 Mild, 3 Smart (was Medium), 4 High, 5 Strict protection. The popup slider now shows each level's name under its number (OFF · MILD · SMART · HIGH · STRICT).
- The download warning shows the host verdict that was actually used, and switches when a late VirusTotal answer changes which one applies.

## 5.0.3
- **Fixed: Show Matrix could show blocked third-party scripts as allowed.** After the browser put the extension's background process to sleep and the popup was the first thing to wake it, Show Matrix replayed the rules without the level rules: every third-party row showed green (e.g. `.fox` scripts on www.foxnews.com at level 3), while the browser kept blocking them. Same cause, also fixed: the toolbar block counter stopped counting and the warning after a blocked exfiltration attempt (protections "Block exfiltrating (phishing) data …") did not open, until the next settings change. Blocking itself was never affected.

## 5.0.2
- **New: Warn about a fake payment-pixel overlay (skimmer scams)** (protection 17, every site from level 1, on by default). Catches two independent signs of a "SuperPixel"/Magecart card-skimming scam: (1) a script claiming to be the Facebook Pixel loader (`fbevents.js`) but served from a host that isn't Facebook's, and (2) a payment-entry field (card number, CVV/CVC) with a cross-origin `<iframe>` drawn on top of it that isn't the site's own payment processor. Either signal alone opens the same red warning page used for ClickFix/ConsentFix — the page itself is never blocked, only warned about. This was originally built for the sibling uBlock-Stripped-Dynamic project; it belongs here instead, reusing the existing warning-page machinery rather than a new UI.
- Protections renumbered (17–31 → 18–32) to make room for the above; your ticks carry over.

## 5.0.1
- Wording fix: the VirusTotal status line ("VirusTotal API key saved — …") now says it checks "the links (URL's) of executable downloads" instead of the vaguer "download addresses."

## 5.0.0
- **Removed: "Block inline scripts (strict content policy)"** (was protection 32, level 4–5 only, outside safer regions). Its strict script-src CSP had no way to tell a site's own legitimate inline `<script>` tags apart from an injected one — both got blocked, so it broke most sites it ran on instead of protecting them. If you had it on, nothing further is blocked by it; everything else at levels 4–5 (WebSocket/WebTransport/WebAssembly blocking, protections 29–31) is unchanged. Major version bump because this removes an enforced protection, not just a UI change.

## 4.7.6
- Accessibility pass on the dark theme: raised `--dim` (used for de-emphasized hint text throughout Options) from a contrast ratio that only barely cleared the WCAG AA minimum to one with real headroom; fixed one leftover spot (an "empty" checkmark in the Show Matrix panel) that used a divider color as text and was nearly invisible.
- Added `docs/STYLE_GUIDE.md`: every text/background color pairing in the UI, computed against the WCAG contrast formula rather than eyeballed, plus a regression checklist for any new color choice.

## 4.7.1 – 4.7.5
- Protections Panel layout and density pass: the Download Protection Options tab now fits a normal laptop screen without scrolling; related controls (DNS-check note, VirusTotal key row, false-positive slider and its explanation, trusted-domains block) were each tightened onto fewer lines; the redundant "Check at VirusTotal" checkbox was removed (saving/clearing the key already controls this); button ordering made consistent (secondary action left, Save right) throughout.

## 4.7.0
- **New: Block pasting a sign-in address into a website** (protection 15, every site from level 2) and **Warn when a site sends you to enter a sign-in code** (protection 16) — both target device-code and consent-phishing flows.
- **New: Fake sign-in window check (Browser-in-the-Browser)** (protection 28, every site from level 2) — catches a fake "Sign in with Google/Microsoft" popup window drawn to look like a real browser chrome.
- ClickFix protection (8) gains a visible warning, macOS/Linux patterns, and two levels instead of one.
- **New "Level 4–5 only" group, outside safer regions**: Block third-party WebSocket connections (29), Block third-party WebTransport connections (30), Block third-party WebAssembly (31), and (removed in 5.0.0) Block inline scripts (32). These, plus every existing "outside safer regions" protection, now also apply on a known high-risk site regardless of your level slider.
- Protections renumbered (15–25 → 17–27) to make room for the above; your ticks carry over.

## 4.6.0
- **New: Block exfiltrating (phishing) data to messaging bots** (protection 11, every site from level 2). Phishing pages send the passwords and card details you type to a Telegram bot, a Discord webhook or a Slack webhook. That transfer is now blocked, and the page gets the red warning "This page tried to send your data away", naming the channel.
- **New: Block exfiltrating (phishing) data to web services** (protection 24, outside safer regions from level 3). The same for form-to-email services and Power Automate workflows, which ordinary sites also use, hence only outside safer regions.
- In both warnings, **Go back** leaves the site completely: it skips the phishing site's own earlier pages (a fake login is often two pages of one site) and opens a new tab when nothing else is left. Nothing about the sites you visited is kept.
- **New: Warn when a password form sends to another site** (protection 14, every site from level 2). A login form that would send your password to a different website is held, and you choose Go back or Continue. Sign-in services (Google, Microsoft, DigiD …), payment services and sites you trust are exempt. Forms without a password field are never touched.
- **New: Block notification prompts that appear without a click** (protection 18, outside safer regions from level 3). Fake "click Allow to continue" pages ask the moment they load; that request is now answered without showing Chrome's prompt. A site that asks after you press its button works as before.
- **Protection 3 is now "Block browser-locker scams (popups, keyboard lock)"**. Besides the endless popups, fake "your PC is infected" pages can no longer: lock the keyboard (Esc always works); go fullscreen again after you have left it (a video player's own fullscreen button still works); show "Leave site?" unless you typed something on the page; keep you on the page with fake history entries (one press on Back gets you out).
- The protections are renumbered: 11 → 12, 12 → 13, 13–15 → 15–17, 16 → 19, 17–20 → 20–23, 21 → 25. Your ticks carry over.
- Data lists refreshed for 4.6: Public Suffix List, popular sites (CrUX September 2026), HaGeZi abused TLDs (5 November 2026) and the free-hosting / dynamic-DNS list.
- Removed as scheduled: the one-time 4.4.5 conversion of site locks on shared hosting suffixes.

## 4.5.9
- GitHub release downloads are now recognised as "currently used to deliver malware" even when GitHub redirects them to an address without a file extension: the link you clicked is checked as well as the final address (as DownloadSentinel already did).
- The "Download ZIP" false-alarm note and the signal count at the top no longer count lines that are shown only as "normal for this kind of download".

## 4.5.8
- The two DNS checks now default to Control D (first) and DNS4EU Protective (second): together they block more malware than Quad9 + Cloudflare. The same pair applies in every region, France included.
- If you never changed your DNS checks, the update moves you to the new pair once. A pair you picked yourself is kept. (Someone who deliberately picked exactly the old default looks the same as someone who never changed it, and is moved too — pick it again in Options to keep it.)
- A file without an extension from a file-sharing site is now rated "Probably Suspicious" from 32 MB (was 50 MB).
- From 650 MB, such a file gets a stronger warning: "large downloads are often used by malware to evade AV detection". It replaces the separate "exceeds VirusTotal maximum" line for that file, so the same fact is not counted twice. Other large downloads keep the VirusTotal line as before.
- A file from a GitHub/GitLab host that is "currently used to deliver malware" no longer also shows the file-sharing platform line (both said the same thing about the host), and the verdict at the top now matches the score instead of sometimes saying "probably safe".
- That warning now weighs −30 instead of −40: on its own it is "Probably Inconclusive" for a download (the warning still opens); it is a minimum, so the verdict only gets worse when other signals already score lower on their own. For sites: orange badge; the dialog opens from level 2 (Medium) up.

## 4.5.7
- Built-in whitelist: 35 entries added from uBlock Stripped Dynamic's list — meeting apps (Zoom, Google Meet, Jitsi, GoTo …), sign-in (Google, DigiD, eHerkenning, BankID, MitID, itsme, Duo, PingOne) and payment (iDEAL, Mercado Pago, Brazilian banks and acquirers).
- 46 suggested entries rejected, each with its reason (chat and file-upload platforms, closed services, whole game-publisher sites, government portals, messaging apps).

## 4.5.6
- Built-in whitelist reviewed entry by entry: Discord (a chat platform whose file hosts deliver malware), itch.io, Steam Community, OpenAI, FingerprintJS, an insurer and an analytics service removed; several entries moved to the right category.
- Downloads from Discord are checked again.
- Visiting a site that is merely misused for malware delivery (Discord, Telegram, bit.ly, Google Drive …) no longer shows the suspicious-site warning; sites someone created on such platforms still do, and downloads from them stay checked.
- A large file (50 MB or more) without an extension from a file-sharing site is now rated "Probably Suspicious": such files are often padded or packed malware.
- The popup's "Trusted:" line now follows the whitelist's own categories.
- The whitelist is available as JSON (docs: builtin-whitelist.json) for DownloadSentinel and uBlock Stripped Dynamic.

## 4.5.5
- Blocked downloads are now paused instead of deleted: "Download anyway" continues the same download (this also works for SharePoint/OneDrive folder downloads), "OK, cancel" or closing the notice deletes it.
- The blocked-download notice keeps working however long it stays open.
- At levels 1–3 a trusted download domain now also covers files the trusted site serves from another server (for example SharePoint zips); at levels 4–5 only the file's own server counts.
- Options explains at which levels the trusted domains lift the download block.

## 4.5.4
- Faster and lighter: the extension wakes up less often, starts faster, and no longer rewrites its rules when a setting that does not affect them is saved.
- Pages are checked against fewer content-script patterns; the suspicious-site warning appears sooner.
- The badge count, risk colour and "Continue once" are kept while the browser stays open.
- Public Suffix List refreshed; every bundled list can now be rebuilt with this project's own tools.
- Backup files from 0.1.x/0.2.0 and Show Matrix overrides saved by 4.2.2 or older are no longer converted.
