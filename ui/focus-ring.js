// ── ui/focus-ring.js ──────────────────────────────────────────────────────────
// Warning windows (4.4.6): the default button has keyboard focus from the start (Enter works) but shows
// NO focus ring, so all buttons look identical. The ring appears once the user navigates by keyboard
// (Tab / arrow keys) and disappears again on the next mouse click. CSS: ui/common.css `.kbd-nav .btn`.
//
// Guards: two document listeners, both owned by this page for its whole (short) life — nothing to release
// when the window closes; no state besides one class on <html>.
// ─────────────────────────────────────────────────────────────────────────────

const KEYBOARD_CLASS = "kbd-nav";
const NAV_KEYS = Object.freeze(["Tab", "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"]);
const root = document.documentElement;

document.addEventListener("keydown", (e) => { if (NAV_KEYS.includes(e.key)) root.classList.add(KEYBOARD_CLASS); });
document.addEventListener("pointerdown", () => root.classList.remove(KEYBOARD_CLASS));
