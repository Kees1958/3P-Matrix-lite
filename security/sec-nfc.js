/*
 * sec-nfc.js — blockSensorsNfc, NFC half.
 *
 * Web NFC has no Permissions-Policy token, so it is blocked by script:
 * NDEFReader is made ABSENT, so a page that feature-detects it sees
 * "not supported". (Motion sensors are blocked by the Permissions-Policy
 * header of the same protection — see core/rule-builder.js.)
 *
 * Body taken from uBlock Stripped Dynamic 10.2.1 sec-scp-fingerprint.js
 * (IdleDetector removed — not part of this protection).
 *
 * Registered by: core/script-builder.js — MAIN world, all frames, document_start.
 */
'use strict';
(function(){
    'use strict';
    try {
        if ( 'NDEFReader' in window ) { delete window.NDEFReader; }
        if ( 'NDEFReader' in window ) {
            Object.defineProperty(window, 'NDEFReader', { value: undefined, configurable: true, writable: true });
        }
    } catch { /* already locked down by the page or another extension — leave it */ }
})();
