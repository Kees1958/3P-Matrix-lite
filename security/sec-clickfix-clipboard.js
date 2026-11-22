/* Blocks clipboard writes whose text looks like a ClickFix attack payload (blockClickFix).

   ClickFix: a page silently puts a command line on the clipboard and then
   socially engineers the visitor into pasting it into Win+R, PowerShell,
   the File Explorer address bar (FileFix), Terminal or a Linux terminal
   ("press Ctrl+V to verify you are human"). The clipboard write itself is
   the automated step, and it is the one this blocks.

   DESIGN — why this matches EXECUTION+OBFUSCATION MARKERS, not "shell-like
   text": developer documentation sites legitimately put commands on the
   clipboard from copy buttons (npm install…, docker run…, curl … | sh), so
   a pattern for shell syntax in general would fire on exactly those.

   4.7.0 — TWO LEVELS (user decision 2026-11-06), every OS's patterns on every
   OS (a scam page picks its payload from the user agent; checking costs nothing):
     STRONG — a hidden/encoded execution flag, a download-and-execute chain, a
              LOLBin fetching from a URL, decoding base64 into a shell, removing
              the macOS quarantine flag together with a download, backgrounding
              a download with its output thrown away, or FileFix padding (a long
              run of spaces that pushes a command out of the visible part of
              the address bar). Always blocked.
     WEAK   — what real install guides also use: plain `curl … | sh`,
              `bash -c "$(curl …)"` (Homebrew), `xattr -d com.apple.quarantine`,
              download + chmod +x + run. Blocked ONLY when the page also shows
              ClickFix instructions (INSTRUCTION_PHRASES: Win+R, Ctrl+Alt+T,
              Ctrl+Shift+V, "verify you are human" …). The page text is read
              once, at that clipboard write only. Accepted false negative: a scam
              page with a weak payload and no such words gets through.
   macOS Script Editor: a link to applescript:// opens Script Editor with a
   script already filled in (a newer macOS variant) — a click on such a link,
   or window.open() of one, is blocked the same way. Not covered: a page that
   sets location.href to such an address itself (not hookable from a page script).

   4.7.0 — VISIBLE WARNING (was silent): the first block on a page dispatches
   CLICKFIX_BLOCKED_EVENT; the ISOLATED-world bridge (security/clickfix-bridge.js)
   tells the service worker, which opens the red warning page (an extension
   page: the scam page can neither cover nor read it). No DOM work is done on
   the hostile page — the reason the protection was silent before.
   The clipboard is left as it was (user decision 2026-11-06): the page's
   command is simply not copied.

   Reads nothing from the clipboard: this only inspects the string the PAGE
   passes to a clipboard write. No clipboardRead/clipboardWrite permission is
   needed (those govern the EXTENSION touching the clipboard).

   Hardened per C35 (Xplainer programming principles): every builtin it relies
   on is captured at injection (document_start, before any page script),
   and every Proxy handler is declared `__proto__: null`, because Proxy
   looks traps up through the handler's prototype chain.
   Cost: nothing until the page writes to the clipboard or clicks a link; then
   a substring pass and, only on a marker hit, a few bounded regexes.
*/
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies of data/constants.js LOG_PREFIX and of the
    // event name in security/clickfix-bridge.js: MAIN-world scripts cannot import.
    // Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';
    const CLICKFIX_BLOCKED_EVENT = '3pmcf-clickfix-blocked';
    try {
        // ── Captured builtins (C35) ──────────────────────────────────────
        const reflectApply = Reflect.apply;
        const regexExec = RegExp.prototype.exec;
        const regexTest = RegExp.prototype.test;
        const strSlice = String.prototype.slice;
        const strToLowerCase = String.prototype.toLowerCase;
        const strIncludes = String.prototype.includes;
        const strReplace = String.prototype.replace;
        const strTrimStart = String.prototype.trimStart;
        const toStr = String;
        const logWarn = console.warn.bind(console);
        const textContentGet = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent').get;
        const closest = Element.prototype.closest;
        const getAttr = Element.prototype.getAttribute;
        const dispatch = EventTarget.prototype.dispatchEvent;
        const CustomEventCtor = CustomEvent;
        const ElementCtor = Element;
        const doc = document;

        // ── CONFIG ───────────────────────────────────────────────────────
        // Only the start of the text is inspected: a ClickFix payload is a
        // command line, while a page legitimately copying an article would
        // otherwise cost a scan of the whole body. FileFix pads with ~140
        // spaces, so the window must hold the padding AND the command.
        const MAX_INSPECTED_CHARS = 2048;
        // Page text read for INSTRUCTION_PHRASES (weak level only): bounded so
        // a huge page cannot make the one read expensive.
        const MAX_PAGE_TEXT_CHARS = 200000;
        // Cheap first pass: if none of these appears, no pattern runs at all
        // (FileFix padding is the exception: checked whenever the text has it).
        // Windows, macOS and Linux execution vectors seen in real campaigns.
        const CHEAP_MARKERS = [
            'powershell', 'pwsh', 'mshta', 'certutil', 'bitsadmin', 'regsvr32',
            'rundll32', 'msiexec', 'conhost', 'wscript', 'cscript', 'curl',
            'wget', 'iex', 'invoke-expression', 'invoke-webrequest', 'irm ',
            'finger', 'cmd', 'osascript', 'base64', 'xattr', 'chmod', 'nohup',
            'python', 'bash', 'sh -c',
        ];
        // STRONG — each requires an execution/obfuscation COMBINATION, never a
        // bare tool name. Always blocked.
        const STRONG_PATTERNS = [
            // Windows
            // powershell/pwsh with a hidden-window, no-profile or encoded flag
            /\b(?:powershell|pwsh)(?:\.exe)?[^\n]{0,120}?[-/](?:w(?:indowstyle)?\s+hidden|nop(?:rofile)?\b|e(?:nc|ncodedcommand)\b)/i,
            // download-and-execute in PowerShell (IEX over a downloaded string)
            /\b(?:iex|invoke-expression)\b[^\n]{0,160}?(?:downloadstring|invoke-(?:webrequest|restmethod)|\birm\b|\biwr\b|net\.webclient)/i,
            /(?:downloadstring|invoke-(?:webrequest|restmethod)|net\.webclient)[^\n]{0,160}?\b(?:iex|invoke-expression)\b/i,
            // LOLBins fetching from a URL
            /\bmshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)/i,
            /\bcertutil(?:\.exe)?[^\n]{0,80}?-(?:urlcache|decode)\b/i,
            /\bbitsadmin(?:\.exe)?[^\n]{0,80}?\/transfer\b/i,
            /\bregsvr32(?:\.exe)?[^\n]{0,80}?(?:\/i:\s*https?:|scrobj\.dll)/i,
            /\brundll32(?:\.exe)?[^\n]{0,80}?(?:javascript:|https?:)/i,
            /\bmsiexec(?:\.exe)?[^\n]{0,80}?\/i\s+https?:/i,
            // finger.exe fetching a "reply" that is piped into cmd (4.7.0)
            /\bfinger(?:\.exe)?\s+\S+@\S+[^\n]{0,40}?\|\s*cmd\b/i,
            // hidden cmd launch
            /\bcmd(?:\.exe)?\s+\/c\s+start\s+\/(?:min|b)\b/i,
            // headless conhost (used to hide a spawned console window)
            /\bconhost(?:\.exe)?[^\n]{0,60}?--headless\b/i,
            // macOS (4.7.0)
            // AppleScript running a download or a shell command
            /\bosascript\b[^\n]{0,200}?(?:\bcurl\b|https?:|do shell script)/i,
            // quarantine flag removed in the same command line as a download
            /\b(?:curl|wget)\b[^\n]{0,240}?\bxattr\s+-[a-z]*[cd]/i,
            /\bxattr\s+-[a-z]*[cd][^\n]{0,240}?\b(?:curl|wget)\b/i,
            // Every OS with a POSIX shell (4.7.0)
            // base64 decoded straight into a shell
            /\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,80}?\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b/i,
            // download started in the background with its output thrown away
            /\bnohup\b[^\n]{0,200}?\b(?:curl|wget)\b[^\n]{0,200}?>\s*\/dev\/null/i,
            /\b(?:curl|wget)\b[^\n]{0,200}?\bnohup\b[^\n]{0,200}?>\s*\/dev\/null/i,
            // python one-liner downloading and executing
            /\bpython[0-9.]*\s+-c\b[^\n]{0,240}?urllib[^\n]{0,240}?\bexec\b/i,
        ];
        // FileFix (4.7.0): a long run of spaces on one line pushes the command
        // out of the visible part of the address bar. Strong when the text also
        // holds an execution marker or a '#' (the comment that hides the rest).
        const FILEFIX_PADDING = /[ \t\u00a0\u2000-\u200b\u3000]{40,}/;
        const FILEFIX_COMMENT = '#';
        const NEWLINE = '\n';
        // WEAK — also used by real install guides: blocked only together with
        // INSTRUCTION_PHRASES on the page.
        const WEAK_PATTERNS = [
            // curl/wget piped straight into a shell (rustup, nvm …)
            /\b(?:curl|wget)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b/i,
            // bash -c "$(curl …)" (Homebrew)
            /\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b/i,
            // macOS quarantine flag removed (unsigned open-source apps document it)
            /\bxattr\s+-[a-z]*[cd][a-z]*\b[^\n]{0,60}?com\.apple\.quarantine/i,
            /\bxattr\s+-[a-z]*c[a-z]*\s/i,
            // download, make executable, run
            /\b(?:curl|wget)\b[^\n]{0,200}?\bchmod\s+(?:\+x|[0-7]{3,4})\b[^\n]{0,120}?(?:&&|;)\s*(?:\.\/|\/tmp\/|\$TMPDIR|~\/)/i,
        ];
        // Instructions only a ClickFix page shows (lower case; '+' compared without
        // the spaces around it — "Win + R" = "win+r").
        const INSTRUCTION_PHRASES = [
            'win+r', 'windows+r', 'windows key+r', '⊞+r', 'ctrl+v', 'cmd+v', '⌘+v',
            'cmd+space', 'command+space', '⌘+space', 'ctrl+alt+t', 'ctrl+shift+v',
            'alt+f2', 'verify you are human', 'verify you\'re human', 'i am not a robot',
            'i\'m not a robot', 'press enter', 'run dialog', 'open terminal',
            'open the terminal', 'open powershell', 'verification steps',
        ];
        const PLUS_SPACING = /\s*\+\s*/g;
        const APPLESCRIPT_SCHEME = 'applescript:';

        let warned = false;                  // guard: the warning is requested once per page

        function lower(s) { return reflectApply(strToLowerCase, s, []); }

        function firstMatch(patterns, text) {
            for ( const pattern of patterns ) {
                const m = reflectApply(regexExec, pattern, [ text ]);
                if ( m !== null ) { return m[0]; }
            }
            return null;
        }

        function pageShowsInstructions() {
            let text = '';
            try { text = toStr(reflectApply(textContentGet, doc.documentElement || doc, []) || ''); }
            catch { return false; }
            const head = reflectApply(strReplace, lower(reflectApply(strSlice, text, [ 0, MAX_PAGE_TEXT_CHARS ])), [ PLUS_SPACING, '+' ]);
            for ( const phrase of INSTRUCTION_PHRASES ) {
                if ( reflectApply(strIncludes, head, [ phrase ]) ) { return true; }
            }
            return false;
        }

        // → the matched text when the write must be blocked, else null.
        function looksLikeClickFix(text) {
            if ( typeof text !== 'string' || text === '' ) { return null; }
            const head = reflectApply(strSlice, text, [ 0, MAX_INSPECTED_CHARS ]);
            const lowerHead = lower(head);
            let cheapHit = false;
            for ( const marker of CHEAP_MARKERS ) {
                if ( reflectApply(strIncludes, lowerHead, [ marker ]) ) { cheapHit = true; break; }
            }
            // One line only: an address-bar payload is a single line, while code
            // copied from a documentation site (aligned comments) has several.
            if ( !reflectApply(strIncludes, head, [ NEWLINE ]) && reflectApply(regexTest, FILEFIX_PADDING, [ head ]) &&
                 (cheapHit || reflectApply(strIncludes, head, [ FILEFIX_COMMENT ])) ) {
                return 'FileFix padding';
            }
            if ( cheapHit === false ) { return null; }
            const strong = firstMatch(STRONG_PATTERNS, head);
            if ( strong !== null ) { return strong; }
            const weak = firstMatch(WEAK_PATTERNS, head);
            if ( weak !== null && pageShowsInstructions() ) { return weak + ' (with ClickFix instructions on the page)'; }
            return null;
        }

        function blocked(matched, via) {
            logWarn(`${LOG_PREFIX} clipboard write blocked (${via}) — looks like a ClickFix command payload: ${matched}. ` +
                'If this site is legitimate, add it to the 3P Matrix allow list (Options) to stop this check there.');
            if ( warned ) { return; }
            warned = true;
            try { reflectApply(dispatch, doc, [ new CustomEventCtor(CLICKFIX_BLOCKED_EVENT) ]); }
            catch { /* the block stands; only the warning is lost */ }
        }

        function isAppleScriptUrl(u) {
            const s = lower(reflectApply(strTrimStart, toStr(u ?? ''), []));
            return reflectApply(strSlice, s, [ 0, APPLESCRIPT_SCHEME.length ]) === APPLESCRIPT_SCHEME;
        }

        // ── 1. navigator.clipboard.writeText() ───────────────────────────
        const clipboard = navigator.clipboard;
        if ( clipboard && typeof clipboard.writeText === 'function' ) {
            clipboard.writeText = new Proxy(clipboard.writeText, {
                __proto__: null,
                apply(target, thisArg, args) {
                    const matched = looksLikeClickFix(toStr(args[0]));
                    if ( matched !== null ) {
                        blocked(matched, 'writeText');
                        // Resolve, not reject: a rejection is a signal the
                        // page can branch on to try another route.
                        return Promise.resolve();
                    }
                    return reflectApply(target, thisArg, args);
                },
            });
        }

        // ── 2. navigator.clipboard.write() (ClipboardItem) ───────────────
        // Text is inside a Blob here, so it cannot be inspected without
        // awaiting it. The payload still has to be text/plain to be
        // pasteable into a shell, so a text/plain item is read and checked.
        if ( clipboard && typeof clipboard.write === 'function' ) {
            clipboard.write = new Proxy(clipboard.write, {
                __proto__: null,
                async apply(target, thisArg, args) {
                    try {
                        const items = args[0];
                        for ( const item of (items ?? []) ) {
                            if ( item?.types?.includes('text/plain') !== true ) { continue; }
                            const text = await (await item.getType('text/plain')).text();
                            const matched = looksLikeClickFix(text);
                            if ( matched !== null ) { blocked(matched, 'write'); return; }
                        }
                    } catch {
                        // Unreadable item: fall through and let it proceed
                        // rather than breaking a legitimate write.
                    }
                    return reflectApply(target, thisArg, args);
                },
            });
        }

        // ── 3. The copy event (setData) ──────────────────────────────────
        // document.execCommand('copy') and programmatic copy events route
        // through here. Registered on window in the capture phase, before
        // any page listener, so the page cannot stop it first.
        window.addEventListener('copy', ev => {
            const dt = ev.clipboardData;
            if ( dt === null || typeof dt?.getData !== 'function' ) { return; }
            const matched = looksLikeClickFix(dt.getData('text/plain'));
            if ( matched === null ) { return; }
            blocked(matched, 'copy event');
            ev.preventDefault();
            ev.stopImmediatePropagation();
        }, true);

        // ── 4. macOS Script Editor links (4.7.0) ─────────────────────────
        window.addEventListener('click', ev => {
            const t = ev.target;
            if ( !(t instanceof ElementCtor) ) { return; }
            const a = reflectApply(closest, t, [ 'a[href]' ]);
            if ( a === null || !isAppleScriptUrl(reflectApply(getAttr, a, [ 'href' ])) ) { return; }
            blocked('applescript: link', 'link click');
            ev.preventDefault();
            ev.stopImmediatePropagation();
        }, true);
        if ( typeof window.open === 'function' ) {
            window.open = new Proxy(window.open, {
                __proto__: null,
                apply(target, thisArg, args) {
                    if ( isAppleScriptUrl(args[0]) ) { blocked('applescript: address', 'window.open'); return null; }
                    return reflectApply(target, thisArg, args);
                },
            });
        }
    } catch {
        // Never break the page: a protection that throws at document_start
        // would be worse than one that is absent.
    }
})();
