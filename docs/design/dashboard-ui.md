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
mono-caps label above, one-line delta/meta below in --ink-2; no plot needed), latest
headline card (severity icon + headline + executive summary, links to Findings), recent
investigations table (8 rows), recent findings list (6 rows). Empty state: "No activity
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
full-width bar, ember on --ember-dim underlay, filled by cumulative output-token share
per step — a literal fuse showing where the budget went; each step's segment is
hoverable (`title`). Then the transcript:

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
appends entries live (htmx poll of the transcript partial). After the transcript: the
rendered report (`report_md` through the existing markdown pipeline, quiet
typographic styles), then the outcome line ("✓ Resolved by operator · 21:58" /
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
- Weight budget: total CSS ≤ ~12 KB, htmx vendored (no CDN at runtime), zero images
  (the wordmark spark is text/SVG inline). No layout shift: mono tabular numbers,
  fixed table column classes.

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

## 6. Still out of scope

"Load 50 more" pagination (lists cap at 200 rows) and the Recommendations page —
deferred; tracked in AGENTS.md §5.3.
