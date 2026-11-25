# 3P Matrix — content firewall — changelog

(Started with 4.5.4: earlier docs packages carried no CHANGELOG.md. Technical detail for 4.5.4 is in
PERF_4.5.3_chrome_engine_and_proposals.md section 6 and the principles doc, v13.)

## 5.1.6
- **Fixed: news sites flagged as payment pages.** A payment provider's hidden helper frame (such as Stripe's invisible measuring frame on CNN) no longer makes a page count as a banking or payment page. Only a payment frame you can see — a real card form — does. So those sites are no longer watched closely, and no longer get tamper warnings for ordinary ad and measuring code.
- **Scam protection list in a clearer order:** blocks first, then warnings, generic before specific. "Warn when opening a site that looks suspicious" is now the last line, so you notice it.
- **Download protection:** the two groups ("On every site" and "Extra — outside safer regions") stand side by side again.

## 5.1.5
- **Fixed: "Form submission canceled because the form is not connected" listed under 3P Matrix** (seen on Ziggo GO). The password-form check held every sign-in form for a moment; a site that rebuilds its page meanwhile lost the form. Now a sign-in form that sends to the site's own address is never held — only a form that sends your password to another site is checked, as before.
- **Fake "your PC is infected" pages now go straight to the red warning page** at the first sign: a loop of dialogs, a keyboard lock, or going fullscreen again after you left it. The warning page's button opens a new tab. Such a page can no longer hold you with "Leave site?". An ordinary page keeps its own "Leave site?" — 3P Matrix no longer watches what you type to decide this.
- **Scam protection is lighter on Windows, Linux and ChromeOS:** the check for links that open the macOS Script Editor is loaded on a Mac only (decided once when the extension starts).
- **Clearer XSS texts:** the Scam protection "Warn about links with hidden code (XSS)" and the tamper sign "Cross-site scripting (XSS)", each with a plain explanation; the XSS warning page explains it the same way.
- **The popup's "Active policy" lists each tab with numbers:** Firewall protection with how many protections are on (and how many of them outside safer regions at level 3), Download protection with the checks a download gets (its own protections, each DNS check that is on, the heuristics, and VirusTotal once you entered a key — at most 6) or off, Scam protection with its number or off, Tamper protection with its number of signs or off.

## 5.1.4
- **New tamper sign: a wallet's recovery phrase sent to another site.** When you type the 12 or 24 words of a crypto wallet's recovery phrase on a page tamper protection watches, and the page sends them to another site, you get a Critical warning at once — whoever has those words owns the wallet.
- **Crypto words start close watching too:** "wallet", "bitcoin", "crypto", "metamask" and similar words in the address — this time also in the site's own name — make tamper protection watch the page (tick "Enable on pages with checkout and payment keywords").
- **New warning sign: a site name starting with "www-"** (like www-featherwallet.com, a fake wallet found on URLhaus). It imitates the "www." of the real site and now counts as suspicious, for opening the site and for downloads. Google Translate's page proxy, which names sites this way, is exempt.

## 5.1.3
- **A new tab layout on the Protections page:** Firewall protection (was Browsing Protection), Download protection, Scam protection (new), Tamper Protection and the Allow (white) list. Only Firewall protection keeps a tick per protection; the other tabs have one switch each, which loads their scripts once per page instead of one by one (faster pages).
- **New tab: Scam protection — one switch, "Enable scam protection".** It covers the warnings about suspicious sites, sign-in code pages and links with script code, the fake browser lock-up (dialog spam), the "paste this command" scams (ClickFix, ConsentFix), notification prompts on every site, payment and protocol handlers, and — at level 3 and up, outside safer regions — dialogs and redirects in frames.
- **New: "Block pasting a one-time or recovery code into a message"** (Scam protection). Pasting a sign-in code, 2FA code or recovery code into a chat or mail box is stopped — the "someone on the phone asks for your code" scam.
- **The Firewall and Download tabs list their protections in one column,** group under group, with "from level" next to each group title.
- **"Block obfuscated code execution" is protection 10 on the Firewall tab** (one protection for eval, Function and the two timers, with its own tick): level 3 outside safer regions, levels 4–5 every site. Protections 10–13 became 11–14; your ticks carry over. On a page tamper protection watches closely, a block also counts as a sign of tampering. The separate "eval on high-risk sites" rule is gone.
- **Tamper protection gives each page a risk rating.** Every sign of tampering adds points; on banking and payment pages they count 1.5 times. Critical (100+) warns at once and stays; High risk (60+) warns and closes after 20 seconds; Suspicious (30+) warns at levels 4–5, at level 3 only outside safer regions, and otherwise only shows "?" on the toolbar icon; Low never warns.
- **The password-form, payment-skimmer and fake sign-in warnings now also count as signs of tampering** (100 points each). They still warn at once with their own warning; the sign then shows in the popup's "This page" box and in any tamper window for that page — no second window.
- **One warning window per page,** listing every sign that was found with the rating. Signs found in the next two seconds are collected first; later signs update the open window. A window you closed only comes back when the rating goes up.
- **Choose when tamper detection watches closely:** four ticks under "Enable tamper detection" — banking and payment pages, a password or card field hidden as a trick, checkout and payment words in the address, and pages of sites you locked to a level (never level 1). Only these four decide it: the level slider no longer adds pages, and a page none of them applies to is not watched and costs nothing (a benchmark like Speedometer no longer gets a "?").
- **"Hidden password or card field" now means hidden as a trick**: a hidden field named like a password or card field, or a field made invisible (or placed off the page) while the form around it is visible. Sign-in forms in a closed menu, dialog or step no longer count.
- **New signs of tampering:** your IBAN sent to another site (checked with the IBAN checksum, like card numbers), and disguised code that was stopped.
- **"Enable tamper detection" has its own card at the top of the Tamper Protection tab,** above the ticks that choose when it watches closely. When it is off, everything under it is shown off: the ticks are unticked and greyed out (your own choices come back when you switch it on again), and the explanation and the list of signs are dimmed. The same goes for "Block risky downloads" while "Warn when a downloaded file looks risky" is off.
- **Fixed: the Scam protection tab explained tamper protection** (risk ratings and points) instead of itself. It now says how scam protection works; the rating explanation is on the Tamper Protection tab, where it belongs.
- **The Tamper Protection list is now plain,** under the heading "Signs of tampering — points add up to the page's risk rating": every sign by name, most serious first; hover it for what it means and its points. The three signs with a warning of their own say "warns at once".
- **New in Download protection: "Download started without a click on the page".** A download that a page starts on its own, without you clicking, counts as an extra warning sign — also for downloads whose file type is only known when they finish.
- **The toolbar icon shows the most serious problem on the page:** "!" (red) — a dangerous site or a High/Critical tamper rating; "?" (orange) — a suspicious site or a Suspicious tamper rating; otherwise a grey number: how many requests the firewall blocked on the page. Click the icon to see what it is about. Chrome counts the blocks itself (only 3P Matrix's own), so 3P Matrix no longer watches every failed request of every page — less work in the background, and no blocks of other extensions in the number.
- **Fixed: a "?" for a suspicious site could disappear** when you went to another page of the same site.
- **New in the popup: a "This page" box** with the site's risk and its reasons, the tamper rating with a Details button (opens the page's tamper window again), a note when you chose "Continue once", and "Firewall blocked N requests on this page" — counted by Chrome when you open the popup. This uses the activeTab permission (no new install warning).
- **One warning per page opening:** a link with script code to a suspicious site no longer opens two warnings that raced each other; the script-code warning comes first.
- **Tamper protection checks outgoing data only once you typed (or your browser filled in) a password, card number or IBAN** on a watched page — before that, the page's network functions are left completely alone. It now also catches card data that leaves as text the page writes into itself (an image written into the page, a style-sheet address).
- **One allow list for every exception,** one line each: `All: site`, `Download: site`, `Firewall: site`, `Scam: site` or `Tamper: site`. A site on its own means All. On Save the list is sorted, `All` removes the site's other lines, and lines with a mistake are named (nothing is saved until they are fixed). Search the list and delete every line of a site at once.
- **Every warning has "Always allow" or "Always ignore",** which adds the right line to the allow list. "Never warn anywhere" and the separate never-warn list are gone.
- **New tickbox "Trust app stores"** in Download settings (on by default). Your own trusted download sites are `Download:` lines on the allow list now.
- **Simpler device protection:** motion sensors are now part of "Block Bluetooth, Serial, HID, USB and motion-sensor access"; the separate sensors/NFC protection is gone. WebTransport is blocked by a network rule only.
- **Fixed: "Leave site? You have unsaved changes" was suppressed** from level 3 outside safer regions (and on high-risk sites). "Block redirects and dialogs from frames" now really applies to frames only: the page itself keeps its own leave prompt, Print button and dialogs. Dialog spam on the page itself is still stopped by Scam protection.
- Tamper warnings that are not critical now stay 20 seconds before closing themselves (was 5).
- Known Chrome limit (unchanged): a shared worker's WebSocket is invisible to extensions, so protection 4 ("Block 3P scripts and frames from abused TLDs") cannot stop its WebSocket part there; protection 12 ("Block third-party WebSocket connections", levels 4–5) does.
- **Fixed: a site's own failed requests were again listed as errors of 3P Matrix** ("Uncaught (in promise) TypeError: Failed to fetch", on the browser's extension page, pointing at sec-no-wasm.js). The WebAssembly protection no longer intercepts the page's network requests at all; it reads where downloaded WebAssembly came from on the response itself. Blocking third-party WebAssembly works as before.

## 5.1.2
- **Better card-skimmer detection in tamper protection:**
  - **Card data hidden in an image address is caught.** Skimmers often send your card number as part of an invisible image's address (or a script, frame or link address) instead of a normal request. Tamper protection now checks those addresses too.
  - **Card numbers are recognised by their value,** not only by the field's name. A field with any name that holds a valid card number (checked with the card checksum) counts, so a shop's or a skimmer's oddly named field no longer slips through.
  - **New warning: a second card form next to the payment provider's.** When a page takes your card in a payment provider's secure frame but also has a card-number field of its own, that is the typical fake form a skimmer adds. Tamper protection warns (High risk).
  - **New warning: a script from a suspicious domain.** On banking and payment pages, scripts from other sites are checked with 3P Matrix's own site checks — domains that imitate a brand or a well-known script provider (such as jquery-cdn.net or googletagmanagr.com), often-abused domain endings and free hosting. Checked on your device; nothing is looked up online.
  - **New: cross-site scripting (XSS) protection, in two halves.** *Browsing Protection:* "Warn when another site sends you a link with script code in it" — another website's link that carries script code in its address (how XSS attacks on sites you are signed in to start) now stops at an amber warning page with *Leave* or *Continue anyway*. *Tamper Protection:* a new finding, "Script code from the address was put into the page" — when a page copies script code from its own address into itself (DOM-based XSS), tamper protection warns (High risk). On an ordinary address this costs nothing.
- **Browsing Protection list in a more logical order:** within each level, network protections first, then risky web technology, then scams (the two "paste this" scams side by side), data theft, and the warnings last. The numbers change (now 1–26); your ticks carry over.
- **The four "obfuscated code" protections are now one:** "Block obfuscated code execution (eval, Function, timers)" covers what the separate eval(), Function(), setTimeout() and setInterval() protections did, with one script per page instead of four. Your tick for the eval() protection carries over; if you had switched off only one of the other three, it is on again as part of this one.
- Tamper Protection's list now names every check the way the other protections do ("Warn when your password is sent to another site"; "Note when …" for the ones that never warn).
- Privacy policy updated for the additions above.

## 5.1.1
- **Tamper protection now starts watching checkout pages from the very first moment.** A checkout, cart or payment word in the page address (in English, Dutch, German, French, Spanish, Italian, Portuguese, Polish, the Nordic, Baltic and Central-European languages, Greek and Bulgarian) makes tamper protection watch closely as the page starts loading — before a card skimmer that loads later can hook anything. Such a word alone never causes a warning about a minor finding: the page still needs a card or IBAN field, a payment provider's frame or a known payment site before those warn.

## 5.1.0
- **New: Tamper Protection — warns when something changes how a page works.** Ad-blocker filter rules, other extensions and hostile scripts can replace a page's built-in functions and quietly edit the data you see (uBlock Origin's json-edit rules are one example). Tamper protection notices that, and on banking, payment and checkout pages it watches closely: data edited after it arrived, your password or card number sent to another site, a sign-in or payment form changed to send elsewhere, hidden password/card fields, a script's tamper check removed. It only warns — it never blocks.
- **One switch, “Enable tamper protection”; the level slider decides how widely it watches:** level 2 banking and payment pages (recognised by the built-in payment list, card or IBAN fields, or a payment provider's frame), level 3 also any page that shows a sign of tampering, levels 4–5 every page. Sites you trust (allow list) are not watched.
- **The warning is a small window of its own** that a page cannot hide. It closes itself after 20 seconds unless you click it (critical warnings stay until you choose). “Never warn on this site” / “Never warn anywhere” add the site to your never-warn list.
- **New tab layout on the Protections page:** Browsing Protection, Download protection, Tamper Protection, Allow (white) list. The Tamper Protection tab has the switch, how it works and your never-warn list on the left, and its protections grouped from Critical to Low on the right (hover a name for the explanation).
- **The never-warn list works like the allow list:** one site and finding per line, with Import, Export, Revert and Save. It is included in “Save settings” / “Restore settings”.
- **The password-form, payment-skimmer and fake sign-in-window warnings are now part of tamper protection:** listed there as Critical, without a number or checkbox of their own; they run whenever tamper protection is on. If you had switched one of them off, it is on again — switch off tamper protection to turn them off.
- **Only the Browsing Protection list is numbered now (1–28).** The two download protections are on the Download protection tab again, without numbers. Your ticks carry over.
- **“Block risky downloads” now needs “Warn when a downloaded file looks risky”**: unticking the warning switches the block off too (its own tick is kept and shown dimmed).
- The level-3 bullet in the popup now counts exactly the protections that apply outside safer regions.
- Privacy policy rewritten to match what the extension does today.
- Data lists refreshed for the new version (top sites, public suffix list, abused TLDs, risky hosts).

## 5.0.9
- No change in how 3P Matrix works. Developer comments in the shared DownloadSentinel library now point to the right places (DownloadSentinel moved its repository to the same layout as 3P Matrix).
- Tools: the check suite and the list tools now also run straight from the GitHub repository (`npm run check` in `tools/`), not only from the three release zips unpacked side by side. The shared Manifest V3 check is again the same file in both projects.

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
