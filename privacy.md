Privacy Policy for 3P Matrix — content firewall

Last Updated: November 2026 (version 5.1.3)

Introduction

3P Matrix — content firewall is a Chrome extension that controls third-party content, adds security protections and warns about suspicious sites, risky downloads and pages that are being tampered with. This policy explains what the extension processes, where, and what — if anything — leaves your device.

In short

3P Matrix does not collect, sell or share personal information. It has no account, no analytics and no server of its own. It keeps no browsing history. Everything below happens inside your browser, except the few online checks listed under "What leaves your device", which only send a site or download address, never anything about you.

What 3P Matrix does not do

Collect personally identifiable information
Track your activity or build a profile of you
Store or send your browsing history
Store or send anything you type into a page (passwords, card numbers, form text or any other input)
Load or run code from the internet
Use analytics or advertising services

How the protections work (all on your device)

Blocking: third-party scripts, frames and requests are blocked or allowed by Chrome's built-in Declarative Net Request engine, according to the level you chose. The extension does not read the content of any request.

Blocked-request count (since 5.1.3): the extension no longer watches or counts blocked requests in the background. Chrome itself counts the requests the extension's rules blocked on a page and shows that number on the toolbar icon; the extension does not see it. When you open the popup, it asks Chrome for that count once (Chrome's activeTab permission, granted only by your click on the icon); the number is shown and not kept. The background only notices a blocked request to the known data-theft channels (messaging bots and similar), to open that warning.

Page protections: small scripts bundled with the extension run inside web pages to stop known scams (fake payment and protocol handlers, browser-locker tricks, ClickFix and ConsentFix clipboard scams, fake sign-in windows, payment-skimmer overlays, obfuscated code) and to warn when a password form sends to another site. They look at what the page does — for example the address a form sends to, or the text a page tries to put on your clipboard — and decide on the spot. They do not read or send the values you type.

Never-share codes (since 5.1.3, Scam protection): when you paste text into a message box (a chat or mail field), the pasted text is checked on the spot, inside the page, for the shape of a one-time or recovery code. If it has that shape, the paste is stopped and a warning opens; the text itself is never stored or sent anywhere — only the fact that a code was stopped reaches the extension's background.

Tamper Protection (since 5.1.0): bundled page scripts check whether a page's built-in functions were replaced and, on banking, payment and checkout pages (or on every page at protection levels 4–5), watch what the page does with your data. To notice a password, card number or IBAN (bank-account number) being sent to another site, the value in a password, card or IBAN field (or in any text field whose value is a card number or an IBAN) is compared with the outgoing request or address INSIDE the page, at that moment. The value is never stored, never sent to the extension's background and never sent anywhere; only the name of the destination site is passed on, to decide whether to warn. On pages it watches closely, the names of the sites the page's scripts come from are also passed to the extension's background and checked there against the extension's built-in lists — on your device, nothing is looked up online. When a page's own address contains script code, the page script also watches where the page puts HTML; only the name of that place (such as "innerHTML") is passed on, never the address or the page content. Since 5.1.3 the page script also says whether the page holds a password or card field hidden as a trick (yes or no — never the field or its value) and when disguised code was stopped (only the name of the function, such as "eval"). The check of outgoing data only starts once you typed (or your browser filled in) a password, card number or IBAN on a watched page; it then also compares the addresses the page loads (images, style sheets, scripts) with what you typed, inside the page. The password-form, skimmer and fake sign-in warnings are also recorded as findings (only the destination or imitated site's name). Each page gets a risk rating from what was found; the rating and the findings are kept in memory for open tabs only. Since 5.1.3 only pages chosen by the four ticks under "Enable tamper detection" are watched closely; other pages send nothing to the extension's background.

XSS link warning (since 5.1.2): when another website opens a page whose address contains script code, the extension compares the address with a few fixed patterns in its background, on your device, and may show a warning. The address is not stored or sent anywhere. When data a site receives is changed by another script, only the names of the changed fields are shown — never their values. What tamper protection finds is kept in memory for open tabs only and cleared when the tab closes.

Show Matrix: when you open Show Matrix for a tab, the extension lists the third-party sites that tab connects to. This list is kept in memory and stops after a few minutes or when you close the panel.

What leaves your device (only these, only for the purpose stated)

Online site check: when a site you open already looks suspicious by the extension's local checks, its domain name (for example example.com — never the full address) is looked up at rdap.org (domain age) and at the two DNS threat-intelligence services you selected (Quad9, Cloudflare Security, Control D, DNS4EU Protective or CleanBrowsing Security). You can set both to None.

Download check: when you download a program, script or archive, its download address may be checked the same way (domain age and DNS checks). Since 5.1.3 the extension also asks the tab that started a download (any download the download protection applies to), once, as the download starts and on your device, whether you clicked or pressed a key there in the last few seconds (yes or no — nothing about what you clicked); the answer is kept in memory only until that download's check is done, and nothing leaves your device. If you entered your own VirusTotal API key, the download's address is also checked at VirusTotal under your key. Without a key nothing is sent to VirusTotal. The file itself is never uploaded.

Browser update check: once a day the extension asks Google's public Chrome version service which version is current for your operating system, to tell you when a security update is waiting. Only the platform name is sent.

What is stored on your device (chrome.storage)

Your protection level and startup level
Protections you switched off
Sites you locked to a level, and your allow list (since 5.1.3 one list with a category per line: All, Download, Firewall, Scam or Tamper)
Your safer-regions (top-level domain) choices
Your Show Matrix overrides
Your DNS check choices
Your download-protection settings, including your VirusTotal API key if you entered one
The result of the last browser update check

For the current browser session only (cleared when the browser closes): the site shown in each open tab with its risk symbol and tamper rating, the sites you chose "Continue once" for in a tab, and downloads that are waiting for your decision.

None of this is sent anywhere. "Save settings" writes it to a file only when you ask; that file contains your VirusTotal API key, so keep it private.

Permissions

declarativeNetRequest: blocking and allowing requests inside the browser.
storage: your settings, as listed above.
webNavigation, tabs: knowing which site a tab shows, to apply your level and show warnings.
webRequest: noticing the start of a new page in a tab (its address, for the site check and the warnings) and a blocked request to a known data-theft channel (no content is read). Since 5.1.3 no longer used to count blocked requests.
activeTab (since 5.1.3): when you click the toolbar icon, the popup may ask Chrome how many requests 3P Matrix blocked on that page.
scripting: registering the bundled page scripts described above, and (since 5.1.3) the one-time "was there a click?" question to the tab that started a download; no remote code.
downloads: checking downloads and holding risky ones until you decide.
alarms: the daily browser update check and cleaning up finished download checks.
Access to all sites: needed to apply the protections on every site you visit.

Children's privacy

3P Matrix collects no personal information from anyone, including children.

Changes to this policy

When a version changes what the extension processes, this policy is updated with it and the date above changes.

Contact

Questions about this policy: open an issue at https://github.com/Kees1958/3P-Matrix-lite
