# Design: HEIM dashboard

The locked system. Every Hallmark run reads this first and pages share it. Change it on purpose; the file is the rule. Approved by the operator on 2026-11-01 (spec: `docs/superpowers/specs/2026-11-01-dashboard-redesign-design.md`).

## System
- Genre: modern-minimal
- Shape of the first page: app screen (a grouped rail, a top bar, panels)
- Theme: custom (vibe: "a Braun monitoring console, one orange signal")
- Axes: warm grey ground / heavy tight system sans / saturated orange signal · posture: instrument panel
- Idea: HEIM reads like a calibrated instrument. Every agent is a channel on one front panel, and nothing lights up unless it needs a hand.

## Tokens
`src/heim/dashboard/static/heim.css` is the source of truth (one stylesheet, no build). `:root` holds the dark values; `[data-theme="light"]` and its `prefers-color-scheme` mirror hold the light overrides, declared identically.
```css
:root {
  --bg: #1C1916;  --panel: #262220;  --raised: #2F2A26;  --line: #3D3733;  --flag-bg: #3A2B1E;   /* light: #E6E2DA #F4F2EC #DDD8CE #CBC4B9 #F7E6D3 */
  --ink: #EFEBE4;  --ink-2: #C3BBB0;  --ink-3: #A79E92;                                        /* light: #1F1A15 #57514A #6B6459 */
  --signal-ink: #F4722F;  --signal-edge: #B8450F;  --on-signal: #1C1916;                       /* light: #BE3F0D #A8360A #FFFFFF */
  --lamp-off: #4A433E;  --lamp-off-hi: #5E5650;  --grille: #4A433E;                            /* light: #8E9499 #B7BCC0 #B8B1A6 */
  --shade: rgb(0 0 0 / 0.45);  --glint: rgb(255 255 255 / 0.06);           /* light: rgb(31 26 21 / 0.14), rgb(255 255 255 / 0.85) */
  /* mode-invariant, :root only */
  --signal: #E8541E;  --signal-hi: #F8713A;  --crit: #D42B1F;  --crit-hi: #F08274;
  --warn: #B07F0A;  --warn-hi: #EFCB6A;  --ok: #9FB0BA;  --ok-hi: #D3DDE2;
  --sans: system-ui, …;  --mono: ui-monospace, …;  --r: 8px;  --r-ctl: 6px;  --dur-micro: 120ms;
}
```
The tool palette (`--tool-*`) and the host slots (`--host-*`) are identity colours and mode-invariant. Spacing is 4 px steps; type is 14 px / 1.45 body, three weights only (400, 600, 800).

## Lamps
A lamp (`.lamp`, and the empty `.dot` inside `.pill`, `.sev`, `.verdict`, `.outcome`) is a 14 px bezelled disc: `radial-gradient(circle at 35% 30%, <hi>, <colour> 65%)` inside a ring of the surface, then a hairline. In the rail the ring is `--bg`. Its colour is the state, the word always sits beside it, and the lamp is `aria-hidden`.

| Class | Meaning | Serves |
|---|---|---|
| `red` | critical, failed | `st-crit` |
| `amber` | warning, degraded, overdue, missed, needs a human | `st-warn`, `st-serious` |
| `orange` | needs you; the current nav item; the engaged segment | approvals |
| `blue` | healthy, complete, resolved | `st-ok` |
| (none) | off, paused, muted, declined, unknown | `st-muted` |
| `ring` | running | `st-running` |

Sizes: `.lamp.lg` 32 px, `.lamp.sm` 12 px. No glyph or emoji is ever a status: words and lamps only.

Contrast: red, orange and amber hold 3:1 on both panels (`--warn` was deepened from `#C9961C` to `#B07F0A` for the light one). Healthy blue-grey (`--ok`) is deliberately quiet, about 2:1 on the light panel: a healthy lamp should not draw the eye, so it is never alone; the word beside it carries the state and the `--line` bezel gives the disc its edge.

## Labels (the operator's ruling)
`.label` is `600 11px/1 var(--mono)`, tracked `0.14em`, upper case, `--ink-3`: card titles, table heads, rail groups, the brand line, the Needs-you task type, the footer. This departs from Hallmark Floor 67 / Reflex 64 on purpose, as do the task-type label above a Needs-you heading (54), arrows on action links (63) and middle-dot meta strings (63). They are recorded in the stamp as one plain line, `ruled: 67 64 54 63`, not as `waive` lines (sloplint rejects waivers on Floor gates); sloplint still lists them, and that is expected. Secondary captions keep lower-case DOM text (tests slice pages on it); CSS sets the caps.

## Components
- **Panels and cards** (`.panel`, `.card`): `--panel`, 1 px `--line`, radius 8 px, `inset 0 1px 0 var(--glint), 0 1px 2px var(--shade)`. Instrument cards (`.cards .card`) reserve 48 px on the right for the `.grille` (a 3 × 7 dot grid). A panel title is `h2` 22 px / 800 / `-0.02em` in `.panel-head`.
- **Display:** the page title `h1` 40 px / 800 / `-0.03em`; figures `.big` 36 px / 800, tabular, no wrap. Mono for hosts, ids, fingerprints, commands, timestamps and the date line.
- **Keys** (`.btn`): 36 px, radius 6 px, panel face, hairline, soft shadow, nudged 1 px when pressed. `.btn.primary` (the legacy `.btn.ember` hook is aliased to it) is `--signal-ink` with `--on-signal` text. Labels in sentence case.
- **Segmented switch** (`m.seg(items)`): a recessed `--raised` tray; plain links; the engaged segment is lifted, carries a `.lamp.sm.orange` and `aria-current="true"`.
- **Tables** (`.tbl`): label heads, 12 px rows, hairlines. A flagged row (`tr.flag`) is `--flag-bg` with a 4 px `--signal` bar.
- **Run strip** (`.runs`): 10 px dots, 8 px apart: `--ink` success, `--crit` failed, `--warn` missed, a hollow ring for the slot not yet received. `.gap` names a monitoring gap with its `.bang`; `.key` explains the dots.
- **Selects** (`.filters select`, `.mselect`): a 1 px `--ink-3` border, not `--line`, so the control's edge holds 3:1 against the panel.
- **Focus:** `outline: 2px solid var(--ink); outline-offset: 2px`, instant, on everything interactive.

## Brand
Lower-case "heim" in geometric arches, the i's dot a lamp in `--signal` (`class="spark"`, `aria-label="HEIM"`). The brand line reads HOMELAB MONITOR / H 01 (Braun's model-number style, with a space). The favicon (`static/logo.svg`) is the compact mark: an ink tile, a lower-case h in off-white, the orange lamp at its shoulder.

## Controls
- Primary: `--signal-ink` fill · radius 6 px · 36 px
- Secondary: panel face with a hairline · same radius and height
- The theme toggle is the rail's Appearance row, a plain link (`?theme=`) that says its state as a word.

## Motion
- Character: severe. `transform` and `opacity` only, `--dur-micro` 120 ms; a key nudges, nothing pulses. Under reduced motion everything stops.

## Exceptions
- **Terminal islands:** `.cmd`, `.rfull`, `.wrap` and `.prose code, .prose pre` sit on `--term-bg` (`#1B1917`, ink `#E9E2D4`, prompt `#E88C3A`) in both modes. A terminal has no light mode.
- **`--ember`** survives as an alias of `--signal-ink` for the day charts and old hooks; new rules use the signal tokens.

## Exports
`heim.css` in this project. No Tailwind, DTCG or shadcn exports.
