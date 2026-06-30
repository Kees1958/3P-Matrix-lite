# 3P-Matrix-lite
uMatrix-style third-party traffic control via Declarative Net Request

3P-Matrix-lite gives you control over third-party traffic in your browser using a simple five-level slider. It is inspired by the classic uMatrix extension but built entirely on Chrome's native Declarative Net Request (DNR) API, which means all filtering happens inside the browser engine itself — no background script reading your traffic, no interception, no data leaving your device.

The idea is straightforward: most privacy and security problems on the web come from third-party scripts and frames that load silently in the background when you visit a page. Trackers, fingerprinting scripts, ad networks, and malicious injections all arrive this way. 3P-Matrix-lite lets you decide how much of that you allow, and makes it easy to dial it back when something breaks.

How it works

When you install the extension, it starts in Easy mode — allow all, which applies no restrictions and lets you observe the default browsing experience. From there you move the slider right to increase protection.

Level 1 — Easy mode - allow all. At first start this extension uses Easy Mode (allow all) as startup mode. You can change the startup mode by clicking on the one (1) in the green rounded square/rectangle in the upper right corner.

<img width="424" height="349" alt="image" src="https://github.com/user-attachments/assets/082e6653-18cb-4270-b74b-9200828fca1e" />




Level 2 — Easy mode with enhanced security blocks the most obviously dangerous categories: third-party connections over plain HTTP, connections to raw IP addresses (a common sign of malicious infrastructure), connections on non-standard ports, and third-party frames. It uses a build-in whitelist to allow 3p-frames from payment services, video embes and captcha's 

<img width="423" height="462" alt="image" src="https://github.com/user-attachments/assets/0200cfa3-abae-4777-8929-8c4bf455c115" />




Level 3 — Easy medium mode adds script blocking on top of level 2. Has the protections of level 2 plus it blocks 3p-scripts not on the TLD white list. The extension uses a build-in whitelist and looks at your browser language settings to add additional country code TLD's (which scope can be adjusted using a slider). This level lowers the third-party exposure considerably but works well on most (95%) of the websites people usually surf or in Europe and North America. 

<img width="434" height="658" alt="image" src="https://github.com/user-attachments/assets/96c1cabe-d36f-4269-8d61-afdfd141893a" />



Level 4 — Medium mode — trust CDN's keeps the same blocking rules as level 5 but makes an exception for any URL that contains "cdn" in the hostname or path and uses the 3P-frame domain whitelist (explained earlier at level).  This is a practical compromise for sites that load their own assets from a CDN host rather than their own domain. Without this exception, many sites break even though their CDN is perfectly legitimate. Your domain whitelist applies at this level. This mode reduces third-party risk considerably, ideal for safely watching adult websites. 

<img width="442" height="660" alt="image" src="https://github.com/user-attachments/assets/a63fd0c8-24d9-4179-85a8-557301855b87" />




Level 5 — Medium mode is the strictest setting. All third-party scripts and frames are blocked. Only domains you have explicitly added to your domain whitelist are allowed through. Use this when you want maximum control and are prepared to whitelist what you need.

<img width="458" height="641" alt="image" src="https://github.com/user-attachments/assets/d7449431-3557-4a97-ab3a-605f05f31cee" />



-

When a site breaks

That is where the built-in request logger comes in. When a site stops working correctly, click the yellow SHOW LOGS button in the popup. The current tab reloads, a full-page logger opens, and every request that the extension blocks is captured in real time with its calling domain, block reason, and URL.

<img width="1544" height="739" alt="image" src="https://github.com/user-attachments/assets/61f71cce-cc7f-4cf1-9da6-cb529ca1aee9" />



