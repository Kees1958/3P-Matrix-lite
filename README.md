# 3P-Matrix-lite
uMatrix-style third-party traffic control via Declarative Net Request

# 3P-Maxtrix-lite

3P-Matrix-lite gives you control over third-party traffic in your browser using a simple five-level slider. It is inspired by the classic uMatrix extension but built entirely on Chrome's native Declarative Net Request (DNR) API, which means all filtering happens inside the browser engine itself — no background script reading your traffic, no interception, no data leaving your device.

The idea is straightforward: most privacy and security problems on the web come from third-party scripts and frames that load silently in the background when you visit a page. Trackers, fingerprinting scripts, ad networks, and malicious injections all arrive this way. 3P-Matrix-lite lets you decide how much of that you allow, and makes it easy to dial it back when something breaks.

How it works

When you install the extension, it starts in Easy mode — allow all, which applies no restrictions and lets you observe the default browsing experience. From there you move the slider right to increase protection.

Level 1 — Easy mode - allow all.

<img width="640" height="400" alt="screenshot_level_1" src="https://github.com/user-attachments/assets/d6fc79af-f7d6-4883-9e96-1075b05fac6d" />


Level 2 — Easy mode with enhanced security blocks the most obviously dangerous categories: third-party connections over plain HTTP, connections to raw IP addresses (a common sign of malicious infrastructure), connections on non-standard ports, and third-party frames. Whitelisted domains always pass through regardless of level.

<img width="640" height="400" alt="screenshot_level_2" src="https://github.com/user-attachments/assets/ddede41a-3f00-4017-93cf-062c41e405d6" />


Level 3 — Easy medium mode adds script blocking on top of level 2. Only domains whose top-level domain is on your TLD whitelist are allowed to load scripts. On a fresh install your TLD whitelist is pre-populated with common TLDs (com, org, io, net etc.) and with the country TLDs of your browser's language settings — so a Dutch browser gets .nl added automatically.

<img width="640" height="400" alt="screenshot_level_3" src="https://github.com/user-attachments/assets/0e9882d9-5ad5-4be8-8363-943e286fd93d" />


Level 4 — Medium mode — trust CDN's keeps the same blocking rules as level 5 but makes an exception for any URL that contains "cdn" in the hostname or path. This is a practical compromise for sites that load their own assets from a CDN host rather than their own domain. Without this exception, many sites break even though their CDN is perfectly legitimate. Your domain whitelist applies at this level.

<img width="640" height="400" alt="screenshot_level_4" src="https://github.com/user-attachments/assets/275b13d2-f004-490c-b5ec-205e2ff3e242" />


Level 5 — Medium mode is the strictest setting. All third-party scripts and frames are blocked. Only domains you have explicitly added to your domain whitelist are allowed through. Use this when you want maximum control and are prepared to whitelist what you need.

<img width="640" height="400" alt="screenshot_level_5" src="https://github.com/user-attachments/assets/d134105a-fc0b-4964-81e8-9c871d768f98" />



When a site breaks

That is where the built-in request logger comes in. When a site stops working correctly, click the yellow SHOW LOGS button in the popup. The current tab reloads, a full-page logger opens, and every request that the extension blocks is captured in real time with its calling domain, block reason, and URL.
<img width="1919" height="713" alt="image" src="https://github.com/user-attachments/assets/6896823e-1a8d-4742-8a88-9cf737e71da5" />


