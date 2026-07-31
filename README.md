# 3P-Matrix-lite
uMatrix-style third-party traffic control via Declarative Net Request

Chrome webstore: https://chromewebstore.google.com/detail/3p-matrix-lite/oljiiikeojepiiaoaicpddpgpfiloejj?pli=1

3P-Matrix-lite gives you control over third-party traffic in your browser using a simple five-level slider. It is inspired by the classic uMatrix extension but built entirely on Chrome's native Declarative Net Request (DNR) API, which means all filtering happens inside the browser engine itself — no background script reading your traffic, no interception, no data leaving your device.

The idea is straightforward: most privacy and security problems on the web come from third-party scripts and frames that load silently in the background when you visit a page. Trackers, fingerprinting scripts, ad networks, and malicious injections all arrive this way. 3P-Matrix-lite lets you decide how much of that you allow, and makes it easy to dial it back when something breaks.

HOW 3P-MATRX-LITE WORKS

When you install the extension, it starts in Easy mode — allow all, which applies no restrictions and lets you observe the default browsing experience. From there you move the slider right to increase protection.

Level 1 — Easy mode - allow all. At first start this extension uses Easy Mode (allow all) as startup mode. You can change the startup mode by clicking on the one (1) in the green rounded square/rectangle in the upper right corner.


Level 2 — Easy mode with enhanced security blocks the most obviously dangerous categories: third-party connections over plain HTTP, connections to raw IP addresses (a common sign of malicious infrastructure), connections on non-standard ports, and third-party frames. It uses a build-in whitelist to allow 3p-frames from payment services, video embeds and captcha's. This mode increases security but works (hassle free) well on 99% of the websites in Europe and North America. 


Level 3 — Easy medium mode adds script blocking on top of level 2. Has the protections of level 2 plus it blocks 3p-scripts not on the TLD white list. The extension uses a build-in TLD whitelist and looks at your browser language settings to add additional country code TLD's (which scope can be adjusted using a slider). This level lowers the third-party exposure considerably but works (hassle free) well on most (95%) of the websites people usually surf to in Europe and North America. 


Level 4 — Medium mode — trust CDN's keeps the same blocking rules as level 5 but makes an exception for any URL that contains "cdn" in the hostname or path and uses the 3P-frame domain whitelist (explained earlier at level).  This is a practical compromise for sites that load their own assets from a CDN host rather than their own domain. Without this exception, many sites break even though their CDN is perfectly legitimate. Your domain whitelist applies at this level. This mode reduces third-party risk considerably, but works well on 90% of the adult websites (without tweaking).


Level 5 — Medium mode is the strictest setting. All third-party scripts and frames are blocked. Only domains you have explicitly added to your domain whitelist are allowed through. Use this when you want maximum control and are prepared to whitelist what you need.


SUGGESTED USE
1. Keep startup mode in level 1 (allow all)
2. Choose for random surfing mode 2 or 3 
3. Choose for risky browsing mode 4

Level 5 is only added for hard core uBlockorigin/uMatrix users

Pictures
<img width="1280" height="800" alt="3P-Matrix-lite" src="https://github.com/user-attachments/assets/92e1b0cf-cc81-4c65-b4e9-12668534cbba" />

<img width="1280" height="800" alt="3P-Matrix-lite2" src="https://github.com/user-attachments/assets/75749941-f25e-4c3d-ad7d-8c476eebe782" />

Automatically add country code's feature
<img width="1719" height="557" alt="image" src="https://github.com/user-attachments/assets/b9301877-58c5-44bb-a8d6-e99b2155c531" />

<img width="1280" height="800" alt="3P-Matrix-lite3" src="https://github.com/user-attachments/assets/2323bb86-bdcc-4667-ba22-8aa89828b1bd" />

<img width="1280" height="800" alt="3P-Matrix-lite4" src="https://github.com/user-attachments/assets/87eaafe7-b2e0-4d03-a276-ccc41774152c" />



