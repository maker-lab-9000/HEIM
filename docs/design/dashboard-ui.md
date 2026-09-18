# HEIM dashboard — UI design spec

Design direction: **the night watch at the hearth**. HEIM is German for *home*; the
product is an agent keeping watch over the house at night and writing down everything it
does. The UI is a dense, dark operations room with one warm light source — ember amber —
reserved for the agent's own activity. The agent works in a shell, so the interface is
**mono-first**: commands, fingerprints, tokens, timestamps and section eyebrows are set
in monospace; prose is quiet system sans. Density like Datadog; identity of its own.

Constraints honored throughout: **no webfonts, no JS framework, no chart library** —
system font stacks, vanilla CSS (~one file), htmx (~14 KB) for partial updates, inline
SVG only where a mark is needed. One color mode (dark) in v1, built on CSS variables so
a light mode can be added without markup changes.

## 1. Tokens

```css
:root {
  /* surfaces — warm charcoal, not neutral black */
  --bg:      #131110;   /* app background */
  --panel:   #1B1917;   /* cards, tables, rail */
  --raised:  #232019;   /* hover rows, active nav, code blocks */
  --line:    #2E2A24;   /* hairline borders, dividers */

  /* ink — warm cast */
  --ink:     #E9E2D4;   /* primary text */
  --ink-2:   #A89E8C;   /* secondary: labels, meta */
  --ink-3:   #6E675B;   /* faint: placeholders, declined, disabled */

  /* the ember — the agent's own light; links, focus, running state, burn line */
  --ember:      #E88C3A;
  --ember-dim:  #8A5524; /* borders/underlays of ember elements */

  /* status (fixed set; ALWAYS paired with icon + label, never color alone) */
  --ok:       #0ca30c;   /* complete, resolved */
  --warn:     #fab219;   /* pending approval */
  --serious:  #ec835a;   /* incomplete, needs_human */
  --crit:     #d03b3b;   /* failed, critical severity */
  /* declined/muted = --ink-3 · running = --ember with pulse dot */

  /* tool badges — validated categorical, fixed per tool (color follows entity).
     Every badge shows the tool NAME next to the dot (required: one CVD pair sits
     in the 6–8 floor band, text label is the secondary encoding). */
  --tool-ssh:        #C97A35;
  --tool-prometheus: #4A8AC2;
  --tool-ha:         #C2609A;
  --tool-discover:   #4F9E5A;
  --tool-proxmox:    #8A6FD1;

  --mono: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;

  --r: 6px;             /* base radius; pills 999px */
  --pad: 8px;           /* base spacing unit; grid gaps 8/12/16 */
}
```

Type scale (rem): 0.6875 eyebrow/mono-caps (letter-spacing .08em) · 0.8125 body-dense /
table cells · 0.875 body · 1.0625 card titles · 1.375 page title · 1.75 hero numbers
(mono, tabular-nums). All numbers everywhere: `font-family: var(--mono);
font-variant-numeric: tabular-nums`.

## 2. Layout

Fixed left rail (200px; collapses to 56px icon rail under 900px), thin top bar, fluid
content column (max 1280px, 16px gutters).

```
┌──────────┬──────────────────────────────────────────────────────┐
│ ✳ HEIM   │  overview                       homelab · 21:42 CET  │
│──────────│──────────────────────────────────────────────────────│
│ Overview │  ┌─────────┐┌─────────┐┌─────────┐┌─────────┐        │
│ Investi- │  │ OPEN    ││ RUNNING ││ PENDING ││ TOKENS  │  KPI   │
│  gations │  │ INCID.  ││ INVEST. ││ APPROV. ││ 24H     │  row   │
│ Incidents│  │  3      ││  1 ●    ││  1      ││ 212k    │        │
│ Findings │  └─────────┘└─────────┘└─────────┘└─────────┘        │
│ Hosts    │  LATEST HEADLINE ────────────────────────────        │
│          │  ⚠ Memory climbing on ubuntu-server …                │
│──────────│  RECENT INVESTIGATIONS ──────────────────────        │
│ ● daemon │  #14 ● running   ubuntu-server  mem_used   9 steps   │
│   up 3d  │  #13 ✓ resolved  homelab        drive_temp 12 steps  │
└──────────┴──────────────────────────────────────────────────────┘
```

Rail: wordmark — a minimal ink-style **house glyph** in ember (tall gable, chimney,
round attic window, two windows, arched door; `static/logo.svg`, also the favicon) +
`HEIM`; nav items
(mono-caps, active item gets an ember left-border + `--raised` bg), and a footer daemon
chip (`● daemon up 3d` — ok dot; `○ daemon unreachable` — ink-3) derived from the
freshest `runs` row. Top bar: page title (lowercase, mono), right side environment chip
+ clock. No breadcrumbs deeper than `investigations / #14`.

## 3. Pages

**Overview** — KPI stat tiles (per dataviz stat-tile spec: mono hero number, small
mono-caps label above, one-line delta/meta below in --ink-2; no plot needed), the
**health card** (severity icon + headline + executive summary from the latest run,
links to Findings, plus a live per-host chip strip: host badge + flag + "1 critical" /
"clear"), the last daily runs, the **tool usage** card (tool badge · agent · model ·
calls · a share bar scaled to the busiest row · blocked · avg time · tokens — single-
hue magnitude, identity carried by the badge), recent investigations table (8 rows),
recent findings list (6 rows). Empty state: "No activity
yet. The daemon records every run here — check back after the next poll."

**Investigations** — the core page. Filter row (status select, host select, trigger
select — plain `<select>`s, htmx `hx-get` swap of the table). Dense table:

| col | render |
|---|---|
| id | mono `#14` |
| status | pill: dot + label (● running pulses at 1.6s; `prefers-reduced-motion` → static) |
| trigger | mono-caps: DAILY / POLLER / MANUAL |
| host | plain |
| fingerprint | mono, --ink-2, truncated middle |
| steps | mono right-aligned |
| tokens | mono right-aligned `in → out` e.g. `128k → 4.2k` |
| duration | mono `4m 12s` |
| started | mono, relative (`2h ago`), title = ISO |

Row click → detail. Running rows: htmx poll `every 5s` on the tbody.

**Investigation detail — THE SIGNATURE.** The page reads as the agent's session
transcript. Header block: host + status pill + trigger + `investigator · claude-sonnet-4-6`
+ tokens in/out + duration + fingerprint (mono). Below it the **burn line**: a 3px
full-width bar, ember on --ember-dim underlay, filled by per-step token share — a
literal fuse showing where the budget went; each step's segment is hoverable
(`title`). Since the runner attributes each turn's usage to the first tool call it
requested (AGENTS.md §5.6), the bar draws **real input-token share**; rows recorded
before that fall back to the older share-of-tool-output-bytes proxy, under its own
label, and the two bases are never mixed in one bar. The caption names whichever is
in use. Then the transcript:

```
│ 01  ▪ prometheus_query                                    1.2s · 2.1 KB
│     $ topk(10, container_memory_working_set_bytes{name!=""})
│     → 10 series · photoprism-photoprism-1 2.90 GiB …        [expand]
│
│ 02  ▪ ssh_diagnostic                                      3.4s · 6.8 KB
│     $ sudo agent-docker stats --no-stream
│     → exit 0 · PhotoPrism 2.703GiB / 17.31% …               [expand]
│
│ 07  ▪ ssh_diagnostic                                 ⛔ blocked · 0.1s
│     $ docker restart photoprism
│     → Command blocked by safety guard (mutating subcommand)
```

Anatomy per entry: left gutter = 2-digit mono step number; tool badge = colored dot
(tool color) + tool name in mono; right meta = duration · result size, mono --ink-2;
command line prefixed `$ ` in mono --ink on --raised; result preview one line, --ink-2,
`[expand]` toggles the stored 400-char preview (native `<details>`, no JS). Blocked
steps: ⛔ + label, left gutter bar turns --crit for that entry. A running investigation
appends entries live (htmx poll of the transcript partial). Each entry's right meta also
carries `~9.0k tok` when the step has an attributed turn usage — the tilde is load
bearing: a multi-call turn credits its whole delta to the first call. After the
transcript: the rendered report (`report_md` through the existing markdown pipeline,
quiet typographic styles), then — when the run stored one — a folded
`Full transcript (N turns)` block (role eyebrow per turn, text in `<pre class="wrap">`),
then the outcome line ("✓ Resolved by operator · 21:58" /
"⚠ Needs human — re-proposed next run").

**Incidents** — store table: severity pill, status (open/clearing/resolved + 🔒 when
investigated-locked), host, metric, fingerprint, seen ×N, missed, first/last seen
(mono). Row expands (details element) to description + linked investigations.

**Findings** — history grouped by run (run header: `daily · 2026-09-18 07:00 ·
claude-opus-4-6 · overall WARNING`, mono). Each finding: severity icon + host +
summary; detail + recommendation inside `<details>`. Verdict column renders when
present ("false positive" pill in --ink-3) — read-only in v1.

**Hosts** — one card per configured host: name (mono, large), role chip, open-incident
count, last finding line, last investigation line. 2–3 col grid.

## 4. Interaction & quality floor

- htmx only for: filter swaps, 5s polling of running investigations/transcripts, lazy
  table pagination ("Load 50 more"). Everything works without JS (initial render is
  complete server-side HTML; polling is enhancement).
- Focus: 2px ember outline, offset 2px, on every interactive element. All meaning is
  icon+label, never color alone. `prefers-reduced-motion`: kill the pulse and any
  transition. Tables are real `<table>` with `<th scope>`.
- Copy: sentence case, plain verbs, no filler. Empty states name the action that fills
  them. Errors say what happened and what to check ("Store unreadable at data/heim.sqlite3
  — is the daemon running with the same volume?").
- Weight budget: total CSS ≤ ~12 KB at v1 (see §5 and §7 for where it has grown to),
  htmx vendored (no CDN at runtime), zero images (the wordmark spark is text/SVG
  inline). No layout shift: mono tabular numbers, fixed table column classes — the
  metrics page's per-category tables share one fixed column geometry (`.mtbl`,
  percentage widths) so stacked tables in a host card read as one grid.

## 5. Actions (v2 — the jobs queue slice)

The dashboard gains a narrow write path: it inserts **action rows only** (jobs,
finding verdicts, suppressions, approval decisions) — the daemon remains the sole
executor and the sole writer of pipeline tables. Every action is a real
`<form method="post">` (works without JS), enhanced by htmx (`hx-post` +
`hx-confirm` where marked ⚠, swapping the nearest panel).

**Button language** — one quiet style everywhere: mono-caps 0.6875rem, transparent
bg, 1px `--line` border, `--ink-2` text; hover: `--ember` border + text; focus: the
standard ember outline. No filled/primary buttons — actions are deliberate, not
promoted. Disabled = `--ink-3` text, no border hover, `title` says why.

**Placement & copy** (sentence case, verb-first):
- Host card footer → `INVESTIGATE` — enqueues a manual investigation for the host.
- Incident expanded row → `INVESTIGATE NOW` (⚠ confirm) · `MARK FALSE POSITIVE`
  (⚠ confirm; suppresses the fingerprint) · when suppressed: `UNMUTE` + a muted
  pill `muted · until <date>` in `--ink-3`.
- Investigation detail header → `RE-RUN` (⚠ confirm; enqueues with retry_of, the
  new run links back: "re-run of #12"). When status is pending_approval:
  `APPROVE` and `DECLINE` side by side (approve gets an ember border at rest —
  the one exception to the quiet style, it's the human-in-the-loop moment).
- Findings rows → inline verdict pair `✓ CONFIRM` / `✗ FALSE POSITIVE`; once set,
  replaced by a verdict pill (confirmed = ok dot; false positive = `--ink-3` pill).

**Feedback:** after a POST the affected panel re-renders with an inline status line
(mono, `--ink-2`): "Queued as job #7 — the daemon picks it up within a few seconds."
Errors follow the store-error copy rules. No toasts, no JS state.

**Queue visibility:** the overview KPI row gains a fifth tile `QUEUED` (jobs
waiting); the investigations list shows queued jobs as ghost rows (`--ink-3`,
"queued · waiting for daemon") above running ones.

**Weight:** this slice deliberately raises §4's CSS budget from ~12 KB to
14 KB (one button style, a feedback line, ghost rows). Still one hand-written
file, still no build step, still the only stylesheet the pages load.

### 5.1 Model choice at trigger time

Every investigate trigger (host card, incident row, CLI) may choose the model. The
dashboard's INVESTIGATE forms gain a compact `<select name="model">` beside the button:
first option `default (<configured model>)` with empty value, then the entries of the new
settings list `investigator_models` (exact Anthropic model ids; empty list = no select
rendered, everything uses the default). The chosen model travels in the job payload and
overrides the investigator agent config for that run only; the investigation row's
`model` column records what actually ran, so the tool-usage and cost breakdowns segment
by it automatically. Approval prompts (Telegram and the pending screen) name the model
when it differs from the default.

## 6. Metrics page (the daily email's data, live)

`/metrics` shows everything the daily report email shows — per-host metric detail over
the 3-day window with trend and status — but live and in the app's own language. Data
comes from the SAME code path as the email (query catalog → aggregate), fetched from
Prometheus on demand with a ~10-minute in-process cache, so numbers and flags always
match what the analyst saw.

- **Header card:** overall status pill · `N crit · N warn · N no-data` (mono) ·
  "3-day window · as of 22:14 (cached 3m)" · a quiet `REFRESH` button (forces a
  refetch; disabled-looking while one is running).
- **Filter row:** host select (all hosts / one), category select — same pattern as
  investigations.
- **Per-host sections:** host name (mono, 1.0625rem) + the host's worst flag as a
  status pill. Inside, one dense table per category that has rows for that host
  (category name as a mono-caps eyebrow):

| col | render |
|---|---|
| status | flag pill: ✓ ok (ok) / ⚠ warn / ✳ crit / · n/a (--ink-3), icon+label |
| metric | label in --ink, `name` (device/mount/chip) in mono --ink-2 |
| current | mono, humanized unit |
| avg | mono --ink-2; min/max in the cell's `title` |
| 3-day trend | the three day averages in mono: `31.1 → 33.2 → 43.3` |
| Δ | ▲/▼/▬ + changePct% in mono; colored by the row's flag ONLY when warn/crit (status colors never decorate healthy rows); `—` when null |

- Rows sort: flag severity first (crit, warn, ok, na), then |Δ%| desc — the eye lands
  on what's moving.
- **Empty/error states:** Prometheus unreachable → "Prometheus unreachable at <url> —
  the numbers here come straight from it. Check `heim check`." Cached data older than
  the TTL still renders with the "as of" timestamp; never show stale data silently.
- Nav: `Metrics` sits between Findings and Hosts in the rail.
- No charts, no new JS: the three-value trend + arrow IS the sparkline, and it stays
  legible in a mono column.

## 7. Observability slice (AGENTS.md §5.6)

- Investigation detail header gains a `cost` kv; the investigations list a `cost`
  column; findings run headers append `· $0.12`; the overview's `tokens 24h` tile
  appends the 24h spend. **An em dash means unpriced** (no entry in
  `settings.model_prices`), never `$0.00` — and a currency other than USD prints its
  code (`EUR 0.42`) rather than a guessed symbol.
- `/telemetry` (not `/metrics`, which is the metric-detail page) serves Prometheus
  text exposition 0.0.4 and is **auth-exempt** like `/healthz`: a scraper cannot carry
  the basic-auth password and the payload is aggregate counters only.
- The rail carries the product's full name under the wordmark ("Homelab Event &
  Incident Monitor"), hidden with the labels on the collapsed 56px icon rail.
- Weight: this slice (transcript block, `.mtbl` geometry, health/tool-usage cards, the
  tagline) takes the stylesheet to ~17 KB. Still one hand-written file, no build step.

## 8. Pagination ("Load 50 more")

Investigations, incidents, and findings lists render the newest 50 rows and end with a
single quiet button `LOAD 50 MORE` (the .btn style, full-width row, centered) when more
rows exist. It is a plain GET link (`?offset=50`, preserving active filters) that
renders the whole page with more rows; htmx enhances it (`hx-get` on the button,
swapping itself for the next rows-fragment + a fresh button) so enhanced clients append
in place. The button disappears when the store is exhausted. Ghost job rows are never
paginated (few, always shown).

## 9. Recommendations page

`/recommendations` — the operator's to-do list, distilled from what HEIM already knows:

- **Sources (union, newest first):** (a) the latest finding per OPEN incident that has a
  non-empty `recommendation` (joined by fingerprint); (b) each complete investigation's
  remediation list (`extract_sections(report_md)["remediation"]`), one row per item.
- Row: host badge · recommendation text (--ink) · source (mono --ink-2: `finding ·
  <metric>` or `investigation #N`) · age · two quiet actions: `DONE` / `DISMISS`.
- Acted rows move to a folded `<details>` "handled (N)" section at the bottom with a
  state pill (done = ok, dismissed = --ink-3) and a timestamp. Acting is idempotent.
- State lives in a `recommendation_states` table keyed by a stable sha1 of
  `(kind, source id, normalized text)` — the dashboard's write surface grows by exactly
  this table. Rows whose source vanished (incident resolved, retention pruned) drop out
  of the active list; their state rows are simply ignored.
- Nav: `Recommendations` between Findings and Metrics. Empty state: "Nothing to act on.
  Findings with recommendations and investigation remediations land here."

## 10. Light mode

The token system was built for two modes; light mode is an override set, not a
redesign. Direction: **morning ash** — the hearth gone cold by daylight: cool-neutral
ash surfaces and neutral ink, with ember as the only warmth left glowing, and the SAME
identity colors. (An earlier warm-cream direction was rejected by the operator as too
close to the common cream/terracotta default — this direction is the ruling.)

```css
[data-theme="light"] {
  --bg: #ECEEED;      /* morning ash — cool neutral, deliberately NOT cream */
  --panel: #FAFBFA;   --raised: #E4E6E4;   --line: #D6D9D6;
  --ink: #22252B;     --ink-2: #5B6169;    --ink-3: #8B9199;
  --ember: #B05E1A;   /* validated 4.0–4.5:1 on the ash surfaces */
  --ember-dim: #E8D0B4;
  /* Tool/host categorical slots and the fixed status palette are
     MODE-INVARIANT: the five identity hexes pass the validator on BOTH
     surfaces (the light-mode CVD floor-band pair is mitigated by the
     ever-present text labels), and the status palette's light-surface
     contrast caveats are mitigated by icon+label per the dataviz rules.
     Do not re-theme them. */
}
```

- Selection: `data-theme` on `<html>`. Resolution order: `heim_theme` cookie →
  `prefers-color-scheme` (via a tiny inline head script so there is no flash) → dark.
  A sun/moon toggle in the topbar cycles auto → light → dark. No-JS path: the toggle is
  a form GET `?theme=<auto|light|dark>` handled server-side (sets the cookie,
  `SameSite=Lax`, 1 year, then redirects back).
- Components read tokens only — any hardcoded dark hex discovered during
  implementation is a bug to fix in place. ONE deliberate exception, and it is light
  mode's signature: **the terminal surfaces stay dark**. Transcript command lines,
  result previews, and code/pre blocks keep their charcoal treatment in light mode
  (scoped rule, e.g. `[data-theme="light"] .cmd, [data-theme="light"] pre { background:
  #1B1917; color: #E9E2D4; }` — literal values allowed HERE only, they are the terminal's
  own colors, not theme tokens). Terminals do not have a light mode; the agent's shell
  keeps its native habitat as dark islands on the paper. The burn line keeps the original
  ember #E88C3A inside those dark blocks.
- Design rationale (recorded so nobody "fixes" it later): the cool ash ground makes
  ember read as the sole warm element — the residual glow in a cold hearth — which keeps
  the accent's agent-activity meaning stronger in light mode than any warm ground could.
  The dark terminal islands complete it: charcoal windows on an ash morning desk. The
  theme toggle uses the lockup's own vocabulary: ☀ light · ☾ dark · ◐ auto.

## 11. Token usage by weekday (overview chart)

A small "token usage" card on the overview (below tool usage): the last **14 days** as
one bar per day — x labels are weekday initials (mo tu we th fr sa su, mono-caps,
today rightmost), bar height = that day's total tokens (investigations by started_at +
runs by run_at, in+out). This shows both the weekly rhythm the user asked about and
recency, without aggregating away real days.

Dataviz rules (binding): single series → NO legend, the card title names it; bars are
the ember accent (tokens ARE agent activity) as thin marks with 4px rounded tops,
2px gaps, on a baseline hairline (--line); value labels are SELECTIVE — only the max
bar carries an inline mono label, every bar has a `title` tooltip with date + exact
count; zero-days render a 2px stub so the axis stays readable. Pure server-rendered
inline SVG (heights precomputed server-side, viewBox fixed) — no JS, no chart library.
Below the chart one mono summary line: `14d: <total> · busiest <weekday> <date> (<n>)`.
Empty state: "No token usage recorded yet."

## 12. Needs attention (overview card)

An overview card for investigations that did NOT finish cleanly — status ∈ {incomplete,
failed, needs_human} — the operator's triage queue. Placed directly under the KPI row's
health card (bad news travels first). Latest 6, newest first, each row: status pill ·
host badge · `#id` link · the reason in one muted line (incomplete_reason, or the
outcome for needs_human) · rel time · a `RE-RUN` action (the existing retrigger form).
More than 6 → a quiet `all (N)` link to /investigations?status=… . Empty state stays
visible as good news: "Nothing needs attention." in --ink-3 with the ok dot.

## 13. Still out of scope

Nothing — as of this revision every previously deferred dashboard item is specced
above.
