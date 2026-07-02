# 3P-Matrix-lite
uMatrix-style third-party traffic control via Declarative Net Request

3P-Matrix-lite gives you control over third-party traffic in your browser using a simple five-level slider. It is inspired by the classic uMatrix extension but built entirely on Chrome's native Declarative Net Request (DNR) API, which means all filtering happens inside the browser engine itself — no background script reading your traffic, no interception, no data leaving your device.

The idea is straightforward: most privacy and security problems on the web come from third-party scripts and frames that load silently in the background when you visit a page. Trackers, fingerprinting scripts, ad networks, and malicious injections all arrive this way. 3P-Matrix-lite lets you decide how much of that you allow, and makes it easy to dial it back when something breaks.

How it works

When you install the extension, it starts in Easy mode — allow all, which applies no restrictions and lets you observe the default browsing experience. From there you move the slider right to increase protection.

Level 1 — Easy mode - allow all. At first start this extension uses Easy Mode (allow all) as startup mode. You can change the startup mode by clicking on the one (1) in the green rounded square/rectangle in the upper right corner.

<img width="424" height="349" alt="image" src="https://github.com/user-attachments/assets/082e6653-18cb-4270-b74b-9200828fca1e" />
-


Level 2 — Easy mode with enhanced security blocks the most obviously dangerous categories: third-party connections over plain HTTP, connections to raw IP addresses (a common sign of malicious infrastructure), connections on non-standard ports, and third-party frames. It uses a build-in whitelist to allow 3p-frames from payment services, video embeds and captcha's. This mode increases security but works (hassle free) well on 99% of the websites in Europe and North America. 

<img width="423" height="462" alt="image" src="https://github.com/user-attachments/assets/0200cfa3-abae-4777-8929-8c4bf455c115" />
-


Level 3 — Easy medium mode adds script blocking on top of level 2. Has the protections of level 2 plus it blocks 3p-scripts not on the TLD white list. The extension uses a build-in TLD whitelist and looks at your browser language settings to add additional country code TLD's (which scope can be adjusted using a slider). This level lowers the third-party exposure considerably but works (hassle free) well on most (95%) of the websites people usually surf to in Europe and North America. 

<img width="402" height="561" alt="image" src="https://github.com/user-attachments/assets/f2191900-d9dd-484b-9086-f772101dd59d" />

Automatically add country code's feature
<img width="1719" height="557" alt="image" src="https://github.com/user-attachments/assets/b9301877-58c5-44bb-a8d6-e99b2155c531" />
-


Level 4 — Medium mode — trust CDN's keeps the same blocking rules as level 5 but makes an exception for any URL that contains "cdn" in the hostname or path and uses the 3P-frame domain whitelist (explained earlier at level).  This is a practical compromise for sites that load their own assets from a CDN host rather than their own domain. Without this exception, many sites break even though their CDN is perfectly legitimate. Your domain whitelist applies at this level. This mode reduces third-party risk considerably, but works well on 90% of the adult websites (without tweaking).

<img width="399" height="588" alt="image" src="https://github.com/user-attachments/assets/0f28dd18-70b5-4d19-94a8-353f58d8036d" />
-


Level 5 — Medium mode is the strictest setting. All third-party scripts and frames are blocked. Only domains you have explicitly added to your domain whitelist are allowed through. Use this when you want maximum control and are prepared to whitelist what you need.

<img width="399" height="491" alt="image" src="https://github.com/user-attachments/assets/a4e87901-06a9-45bf-b33e-192b79800342" />

-


When a site breaks

That is where the built-in request logger comes in. When a site stops working correctly, click the yellow SHOW LOGS button in the popup. The current tab reloads, a full-page logger opens, and every request that the extension blocks is captured in real time with its calling domain, block reason, and URL.

<img width="1544" height="739" alt="image" src="https://github.com/user-attachments/assets/61f71cce-cc7f-4cf1-9da6-cb529ca1aee9" />

-

Using the lock (pin security level for website)

You can pin the protection level up to 100 website either for allowing a website or always containing a website automatically.
The 100 maximum is fixed and uses a first in first out to keep it at a maximum of 100. This FIFO approach is especially
chosen so people can´t see what websites you want to contain in a 3P-Matrix-lite (uMatric users will recognise the lock :-).

<img width="947" height="619" alt="image" src="https://github.com/user-attachments/assets/e59d8768-5f3f-4ecc-a9a4-56698cd219d6" />
-


SUGGESTED USE
1. Keep startup mode in level 1 (allow all)
2. Choose for random surfing mode 2 or 3 
3. Choose for risky browsing mode 4

Level 5 is only added for hard core uBlockorigin/uMatrix users






