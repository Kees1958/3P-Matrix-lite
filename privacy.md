rivacy Policy for 3P-Matrix-lite

Last Updated: June 2026

Introduction

3P-Matrix-lite is committed to protecting your privacy. This Privacy Policy explains what information the extension processes and how it is used.

Information We Collect

3P-Matrix-lite does not collect, store, transmit, or share any personal information about users.

Specifically, 3P-Matrix-lite does not:


Collect personally identifiable information (PII)
Track user activity or browsing behaviour
Store or transmit browsing history
Collect or read the content of any web page
Create user profiles or analytics data
Contact any external server or API


How 3P-Matrix-lite Works

The extension registers filtering rules with Chrome's native Declarative Net Request (DNR) engine. These rules block or allow third-party network requests based on the protection level you have chosen. The filtering happens entirely inside the browser — the extension never reads, inspects, or transmits the content of any request.

When you move the slider to a higher protection level, the extension updates the set of active DNR rules. When you add a domain or TLD to a whitelist, that entry is saved locally in your browser and used to generate an allow rule. Nothing is sent anywhere.

The Request Logger

The built-in request logger is strictly opt-in and is designed for debugging only.


Logging is off by default and only activates when you explicitly click SHOW LOGS
When active, the logger captures the URL, request type, calling domain and timestamp of requests that were blocked by the extension's own rules
This data is stored temporarily in chrome.storage.local on your device only
All log data is automatically deleted after 5 minutes, or immediately when you click Stop & close
Log data is never transmitted to any server or third party


Third-Party Services

3P-Matrix-lite does not use any third-party services. It does not connect to any external API, analytics platform, or remote server of any kind. All processing happens locally within your browser using Chrome's built-in extension APIs.

Data Storage

The following settings are stored locally on your device using chrome.storage.local:


Your chosen protection level (1–5)
Your startup level preference
Your domain whitelist entries
Your TLD whitelist entries


None of this data is ever transmitted outside your browser.

Important Notice

3P-Matrix-lite does not upload, transmit, or share:


The content of any web page you visit
Any request payload or response data
Any personal data of any kind
Your browsing history
Any information about which websites you visit


Changes to This Privacy Policy

This Privacy Policy may be updated from time to time. Any changes will be reflected by updating the "Last Updated" date at the top of this document.
