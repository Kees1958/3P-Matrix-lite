# Style Guide — 3P Matrix dark theme

Single-theme extension (no light mode). Every ratio below is **computed**
against the real `:root` token values in `ui/common.css` (WCAG
relative-luminance formula: `lin(c)=c/12.92` if `c≤0.03928` else
`((c+0.055)/1.055)^2.4`, `L=0.2126·lin(r)+0.7152·lin(g)+0.0722·lin(b)`,
`ratio=(max(L)+0.05)/(min(L)+0.05)`), not eyeballed. First done 4.7.6.

Minimum bar used throughout: **4.5:1** for normal text, **3:1** for
large/bold text (~18px+ regular or ~14px+ bold) and non-text UI
components (meaningful borders, icon-only controls). A decorative
divider that carries no information on its own (a card edge, a panel
separator) is not held to the 3:1 bar.

## Core tokens (verified)

| Token | Value | vs `--bg` | vs `--surface` | Status |
|---|---|---|---|---|
| `--muted` | `#C0C7D4` | 11.11:1 | 10.03:1 | ✅ text-safe everywhere |
| `--dim` | `#9CA5B9` | 7.63:1 | 6.89:1 | ✅ text-safe (raised in 4.7.5 from `#7C8496`, which cleared 4.5:1 on `--surface` by only 0.04 — too thin a margin for 11px hint text) |
| `--bright` | `#FFFFFF` | 18.87:1 | 17.03:1 | ✅ text-safe |
| `--yellow` | `#FFD84D` | 13.64:1 | 12.32:1 | ✅ text-safe |
| `--link` | `#93C5FD` | 10.46:1 | — | ✅ text-safe |
| `--accent` | `#FACC15` | 12.32:1 | 11.12:1 | ✅ text-safe |
| `--mint` | `#6EE7B7` | 12.38:1 | 11.17:1 | ✅ text-safe |
| `--block` | `#F87171` | 6.82:1 | 6.16:1 | ✅ text-safe (used only inside `.dw-box`, which fixes its own background to `--surface` — never renders on the dynamic warning-page banner colour) |
| `--border` | `#252A38` | 1.32:1 | — | decorative divider only — **not** text-safe, **not** a meaningful-component border |
| `--border-2` | `#3A4152` | — | 1.67:1 | decorative divider only, same as `--border` |

## Solid-fill button text (verified)

Per-fill text colour, computed against each fill directly (not against
`--bg`/`--surface` — a filled button's text sits on the fill, not the
page):

| Fill token | vs black (`--bg` #0F1117) | vs white (`--bright`) | What 3P Matrix actually uses |
|---|---|---|---|
| `--accent` (#FACC15) | 12.32:1 | 1.53:1 | `color: var(--bg)` — `.btn-primary`, `.add-btn`, `.action-btn[aria-expanded]` ✅ correct |
| `--choice-safe` (#4ADE80) | 10.83:1 | 1.76:1 | `color: #0F1117` via the shared `.btn.btn-safe,.btn.btn-careful,.btn.btn-risky` rule ✅ correct |
| `--choice-risky` (#FF8A1F) | 8.00:1 | 2.14:1 | same shared rule ✅ correct |
| `--choice-careful-bg` (#2A2F3C, dark fill) | — | — | text is `--choice-careful-text` (#FFE14D), 10.27:1 ✅ correct — dark fill, so bright text is right here, unlike the three above |

**Rule of thumb for any new solid-fill button**: bright/saturated fills
(amber, green, orange) need **black** text, not white — white never
clears 4.5:1 on any of them. Only a *dark* fill (like
`--choice-careful-bg`) should use bright text. This project already
gets it right everywhere it's used; keep doing it this way rather than
reaching for white as a default.

## Fixed this pass (4.7.6)

| Location | Was | Now | Ratio |
|---|---|---|---|
| `ui/matrix.css` `.td-check.empty` | `color: var(--border)` (a divider token used as text) | `color: var(--dim)` | 1.19:1 → 7.63:1/6.89:1 |

Same bug class as 4.7.5's `--dim` fix: a non-text token pressed into
service as text. `--dim` is the one verified de-emphasis-text token in
this codebase — reuse it rather than introducing a second one-off value.

## Borders as dividers vs. components

`--border` (1.32:1 vs `--bg`) and `--border-2` (1.67:1 vs `--surface`)
both fail the 3:1 component bar, and that's fine: every current use is a
decorative divider (`.card`, `.prot-group`, `.tab-bar` underline,
`.color-preview` swatch edge) — none of them is the *only* way a user
tells two things apart; a label, fill, or state always carries that too.
Neither token should be used as the sole signal for something that
actually needs 3:1 (e.g. a border that is itself the only indication a
control is focused or disabled) — if that need comes up, verify a new
value against this same bar before using either token for it.

## Regression checklist

Before shipping a new color token or a new use of an existing one:
- [ ] Is it used **as text**? If yes, compute its ratio against the
      *actual* background it sits on (not just `--bg`/`--surface` in the
      abstract) and clear 4.5:1 (or 3:1 only if genuinely large/bold).
- [ ] Is it a **solid-fill button background**? Check the fill against
      both black and white text directly — don't assume white is safer
      just because the fill is dark-mode-bright.
- [ ] Is it a **border**? Decide first whether it's decorative or the
      sole carrier of a meaningful distinction; only the latter needs 3:1.
- [ ] If a token is already verified safe for a purpose (`--dim` for
      de-emphasized text, `var(--bg)` for text-on-bright-fill), reuse it
      rather than picking a new value — one proven value per role, shared
      across the whole extension, not a fresh guess per site.
