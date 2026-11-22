/*
 * password-form-guard.js — warnPasswordForms (3P Matrix 4.6.0), ISOLATED-world half
 * "Warn when a password form sends to another site".
 *
 * When a form WITH a password field is about to be sent (a submit event, or form.submit() handed over by
 * security/sec-form-submit-hook.js), the submission is held and the service worker is asked whether its
 * destination is another site (core/password-form.js — page taken from the message SENDER, C28). No warning →
 * the form is sent at once. Warning → an in-page dialog: "Go back" leaves the site (core/leave-site.js, no history
 * kept), "Continue" sends the form. Forms without a password field are never touched.
 *
 * Cost: nothing until a form is submitted; then one selector query; for a password form one message round-trip.
 * Fail-open guard: if the service worker cannot answer (extension reloaded, error), the form is sent — a login
 * must never be broken by the check itself.
 * Lifecycle: the dialog host is created on demand, removed (with its listeners) on every outcome; one dialog at
 * a time (`openDialog`). The re-send of an approved form is marked once (`approved`) so this listener lets it pass.
 * In-page on purpose (C47 reviewed, 5.0.6): the dialog HOLDS the form, so a page that removes or hides it only
 * leaves its own form unsent — removing it gains the page nothing. The buttons act on real clicks only (isTrusted).
 * World: ISOLATED, all frames, document_start. Classic script (content scripts cannot import).
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies of shared values (this script cannot import); kept equal to their sources
    // by tools/check-shipped-terms.mjs: LOG_PREFIX (data/constants.js), MSG_* (data/message-types.js),
    // PASSWORD_SUBMIT_EVENT (security/sec-form-submit-hook.js).
    const LOG_PREFIX = '[3PMCF]';
    const MSG_CHECK_PASSWORD_FORM = 'CHECK_PASSWORD_FORM';
    const MSG_PASSWORD_FORM_LEAVE = 'PASSWORD_FORM_LEAVE';
    const PASSWORD_SUBMIT_EVENT = '3pmcf-password-submit';
    const PASSWORD_SELECTOR = 'input[type="password"]';
    const TEXT = Object.freeze({
        title: 'This page sends your password to another site',
        intro: 'Phishing pages look like a real login page but send what you type somewhere else. Only continue if you expected to sign in at:',
        back: 'Go back',
        cont: 'Continue',
        brand: '3P Matrix — content firewall'
    });
    // Dialog look: one block of CSS inside a closed shadow root (the page can neither style nor click it).
    const DIALOG_CSS = [
        ':host{all:initial}',
        '.bg{position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:2147483647}',
        '.dlg{max-width:440px;margin:16px;background:#181C26;color:#FFFFFF;border:2px solid #F87171;border-radius:8px;padding:20px;font:14px/1.45 system-ui,sans-serif}',
        '.brand{font:12px ui-monospace,monospace;color:#C0C7D4;margin-bottom:8px}',
        'h1{font-size:18px;margin:0 0 8px;color:#F87171}',
        '.host{font:14px ui-monospace,monospace;background:#0F1117;padding:6px 8px;border-radius:4px;margin:10px 0 16px;word-break:break-all}',
        '.act{display:flex;gap:10px;flex-wrap:wrap}',
        'button{flex:1;min-width:140px;height:40px;border:0;border-radius:6px;font:600 14px system-ui,sans-serif;cursor:pointer;color:#0F1117}',
        '.back{background:#4ADE80}.cont{background:#FF8A1F}',
        'button:focus-visible{outline:3px solid #FFFFFF;outline-offset:2px}'
    ].join('');

    const approved = new WeakSet();          // forms whose next submit is the approved re-send
    let openDialog = null;                   // guard: one dialog at a time

    function hasPassword(form) {
        try { return !!form.querySelector(PASSWORD_SELECTOR); } catch { return false; }
    }

    // The destination as the browser resolves it: the submit button's formaction wins over the form's action.
    function destinationOf(form, submitter) {
        if (submitter && submitter.hasAttribute && submitter.hasAttribute('formaction')) return submitter.formAction;
        return form.action;
    }

    // Sends the form for real: a submitter-driven submit goes through requestSubmit (validation, page handlers);
    // a form.submit() hand-over uses this world's own (unhooked) submit, exactly what the page asked for.
    function send(form, submitter, viaSubmitCall) {
        if (viaSubmitCall) { form.submit(); return; }
        approved.add(form);
        try { form.requestSubmit(submitter && submitter.form === form ? submitter : undefined); }
        catch { approved.delete(form); form.submit(); }
    }

    function closeDialog() {
        if (!openDialog) return;
        openDialog.host.remove();
        document.removeEventListener('keydown', openDialog.onKey, true);
        openDialog = null;
    }

    function showDialog(destHost, onContinue) {
        closeDialog();
        const host = document.createElement('div');
        const root = host.attachShadow({ mode: 'closed' });
        const style = document.createElement('style');
        style.textContent = DIALOG_CSS;
        const bg = document.createElement('div'); bg.className = 'bg';
        const dlg = document.createElement('section'); dlg.className = 'dlg';
        dlg.setAttribute('role', 'alertdialog');
        const brand = document.createElement('div'); brand.className = 'brand'; brand.textContent = TEXT.brand;
        const h1 = document.createElement('h1'); h1.textContent = TEXT.title;
        const intro = document.createElement('p'); intro.textContent = TEXT.intro;
        const where = document.createElement('div'); where.className = 'host'; where.textContent = destHost;
        const act = document.createElement('div'); act.className = 'act';
        const back = document.createElement('button'); back.className = 'back'; back.type = 'button'; back.textContent = TEXT.back;
        const cont = document.createElement('button'); cont.className = 'cont'; cont.type = 'button'; cont.textContent = TEXT.cont;
        act.append(back, cont);
        dlg.append(brand, h1, intro, where, act);
        bg.append(dlg);
        root.append(style, bg);
        back.addEventListener('click', (e) => {
            if (!e.isTrusted) return;
            closeDialog();
            chrome.runtime.sendMessage({ type: MSG_PASSWORD_FORM_LEAVE })
                .catch((err) => console.warn(LOG_PREFIX, 'password form: go back failed', err));
        });
        cont.addEventListener('click', (e) => { if (!e.isTrusted) return; closeDialog(); onContinue(); });
        function onKey(e) { if (e.key === 'Escape' && e.isTrusted) { e.stopPropagation(); closeDialog(); } }   // Esc = cancel, nothing sent
        document.addEventListener('keydown', onKey, true);
        (document.documentElement || document).append(host);
        openDialog = { host, onKey };
        back.focus();
    }

    async function check(form, submitter, viaSubmitCall) {
        let res = null;
        try {
            res = await chrome.runtime.sendMessage({ type: MSG_CHECK_PASSWORD_FORM, actionUrl: String(destinationOf(form, submitter) || '') });
        } catch (err) {
            console.warn(LOG_PREFIX, 'password form check unavailable — sending the form', err);   // fail open
        }
        const decision = res && res.ok ? res.data : null;
        if (!decision || !decision.warn) { send(form, submitter, viaSubmitCall); return; }
        showDialog(decision.destHost, () => send(form, submitter, viaSubmitCall));
    }

    // 5.0.6 (C47): on WINDOW, capture phase, registered at document_start — the earliest point in the event's path,
    // so a page's own window/document capture listener cannot stop the submit before this check sees it.
    window.addEventListener('submit', (e) => {
        const form = e.target;
        if (!(form instanceof HTMLFormElement)) return;
        if (approved.has(form)) { approved.delete(form); return; }   // the approved re-send: let it go
        if (!hasPassword(form)) return;
        e.preventDefault();
        e.stopImmediatePropagation();                                // page handlers run on the approved re-send
        check(form, e.submitter, false);
    }, true);

    window.addEventListener(PASSWORD_SUBMIT_EVENT, (e) => {
        const form = e.target;
        if (form instanceof HTMLFormElement) check(form, null, true);
    }, true);
})();
