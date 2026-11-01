# HEIM dashboard — UI design spec

> **Superseded direction (2026-11-01, the operator's ruling).** The "night watch at the
> hearth" dark direction, its "morning ash" light mode and the house glyph are retired.
> The dashboard is now the operator's **Braun-inspired monitoring console**, locked in
> [`design.md`](../../design.md) at the repo root (tokens, lamps, labels, components,
> brand, motion) and specified in
> `docs/superpowers/specs/2026-11-01-dashboard-redesign-design.md`. §1, §2 (the rail)
> and §10 below describe the console; the other sections still hold for behaviour, and
> where they name the old visual vocabulary (ember borders, mono-caps buttons, pulse
> dots, glyph icons) `design.md` wins.

Design direction: **a calibrated instrument**. Every agent is a channel on one front
panel, read at a glance, and nothing lights up unless it needs a hand. A warm grey
ground, off-white panels, brown-black ink and one orange signal; red and amber lamps are
reserved for conditions that matter, and healthy states stay quiet.

Constraints honored throughout: **no webfonts, no JS framework, no chart library** —
system font stacks, vanilla CSS (one file), htmx (~14 KB) for partial updates, inline
SVG only where a mark is needed. Light and dark modes from one token set.

## 1. Tokens

The token set lives in `static/heim.css` and is documented in [`design.md`](../../design.md):
surfaces (`--bg`, `--panel`, `--raised`, `--line`, `--flag-bg`), ink (`--ink`, `--ink-2`,
`--ink-3`), the orange for text and key faces (`--signal-ink`, `--signal-edge`,
`--on-signal`), and the mode-invariant lamp colours (`--signal`, `--crit`, `--warn`,
`--ok`, each with a `-hi` highlight). `:root` holds the dark values; the light override
set and its `prefers-color-scheme` mirror close the file, declared identically. The tool
palette (`--tool-*`) and the host slots (`--host-*`) are unchanged identity colours.
`--ember` survives only as an alias of `--signal-ink`.

Type: system sans, 14 px / 1.45 body, three weights (400, 600, 800); the page title 40 px
/ 800; panel titles 22 px / 800; figures 36 px / 800, tabular. Labels (card titles, table
heads, rail groups) are mono caps, tracked: the operator's ruling, see `design.md`. Mono
for hosts, ids, fingerprints, commands, timestamps and the date line.

## 2. Layout

A fixed, grouped left rail (232 px; on phones under 60rem it becomes a wrapped row of
lamp-chips above the page), a top bar inside the page column, and a page column of up to
1440 px.

```
┌───────────────────┬──────────────────────────────────────────────────────┐
│ heim              │  Overview                      4 hosts · 21:42 CET   │
│ HOMELAB MONITOR   │  Sunday, 1 November                                  │
│ H 01              │  ┌────────────┐┌────────────┐┌────────────┐          │
│ WORKSPACE         │  │ panels and instrument cards …                     │
│ (●) Overview      │                                                      │
│ ( ) Agents      7 │                                                      │
│ ( ) Investig.   2 │                                                      │
│ ( ) Incidents   5 │                                                      │
│ INFRASTRUCTURE    │                                                      │
│ INSIGHTS          │                                                      │
│───────────────────│                                                      │
│ ( ) Connected     │                                                      │
│ ( ) Appearance    │                                                      │
└───────────────────┴──────────────────────────────────────────────────────┘
```

Rail: the brand (lower-case "heim" in geometric arches, the i's dot an orange lamp;
`class="spark"`, `aria-label="HEIM"`; the favicon `static/logo.svg` is the compact h
mark), the brand line HOMELAB MONITOR / H 01, then three groups: **Workspace**
(Overview, Agents, Investigations, Incidents), **Infrastructure** (Hosts, Metrics,
Security), **Insights** (Findings, Recommendations, Costs). Every item has a lamp, orange
when current (`aria-current="page"`); Agents, Investigations (running + pending
approval), Incidents (open) and Hosts carry a count. The footer holds the daemon line
(`class="daemon"`: **Connected** / **Daemon quiet** / **No heartbeat yet**, with
"Synced 2m ago", read from the newest poll heartbeat in `agent_runs`, falling back to
the `runs` table) and the **Appearance** switch. Top bar: the page title, the date in the
configured timezone, "n hosts · HH:MM TZ" and a slot for a page's segmented switch.

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
`seen ×N` counts *sightings by the path that owns the row*, and those cadences differ:
a `[metric] ` (threshold-detected) incident is seen once per poll (~288/day), an
`[alert] ` one only on state changes, and a daily-born one once per run (2/day) — so
compare the column within an ownership prefix, never across them.

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
rows exist. It is a plain GET link (`?offset=50`, preserving active filters) that renders
the whole page at the next window; htmx enhances it by swapping the rows container for
that window in place. The button disappears when the store is exhausted.

RULING (2026-09-19, amended after implementation): this spec originally said enhanced
clients *append* to the rows already on screen. The implementation SWAPS to the next
window instead, for a concrete reason — the investigations table carries a 5-second live
poll that re-renders its tbody, which would silently clobber appended rows and leave the
operator staring at a list that shrank on its own. Swap also keeps the htmx path and the
no-JS path showing the same thing, which append does not. The spec now describes the
swap. If the label ever reads as a promise to append, rename the button ("NEXT 50")
rather than reintroducing the clobber. Ghost job rows are never
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

Light and dark are one token set (§1, `design.md`): `:root` is dark, and
`[data-theme="light"]` plus its `prefers-color-scheme` mirror override the surfaces, the
ink and the signal text colours. The lamps, the tool and host palettes and the terminal
islands are mode-invariant.

- Selection: `data-theme` on `<html>`. Resolution order: `heim_theme` cookie →
  `prefers-color-scheme` (pure CSS, the mirror block) → dark. The rail's **Appearance**
  row cycles auto → light → dark and says its state as a word (Auto, Light, Dark; no
  emoji, the operator's ruling of 2026-11-01). No-JS path: the toggle is a plain GET link
  `?theme=<auto|light|dark>` handled server-side (sets the cookie, `SameSite=Lax`,
  1 year, then a 303 back with the rest of the query string kept).
- Components read tokens only. ONE deliberate exception: **the terminal surfaces stay
  dark** in both modes (`.cmd`, `.rfull`, `.wrap`, `.prose code, .prose pre` on
  `--term-bg` `#1B1917`, ink `#E9E2D4`, the prompt in `#E88C3A`). A terminal has no light
  mode.
- The "morning ash" set and its ☀ ☾ ◐ toggle are superseded (2026-11-01).

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
More than 6 → a quiet `all (N)` link to /investigations.

RULING (2026-09-19): this line originally named `/investigations?status=…`, which cannot
be honoured — the card spans three statuses (incomplete, failed, needs_human) and the
filter accepts one, so any single query string would hide two-thirds of the queue behind
a link that claims to show all of it. The link goes to the unfiltered list. The better
fix is a filter that accepts a set of statuses; until then, unfiltered-but-complete beats
filtered-but-lying. Empty state stays
visible as good news: "Nothing needs attention." in --ink-3 with the ok dot.

## 13. Cost monitor (`/costs`)

Where the money goes, by model. Nav after Metrics. Windows: `7d | 30d | all`
(query param, default 30d; a quiet segmented control of three GET links).

- **Header:** total spend for the window in mono (`$4.82`), calls, tokens in → out,
  and "prices from settings — models without a price render —".
- **By model** — the main table, one row per model actually used in the window:
  model (mono) · role chip (investigator / analyst — derived from which table the rows
  came from) · calls · tokens in · tokens out · cost · a share bar (that model's cost as
  a fraction of the window total; single-hue ember magnitude encoding, identity carried
  by the model name). Sorted by cost desc, unpriced models last with a `—` cost and a
  `no price` chip.
- **By day** — the existing 14-day bar chart pattern (spec §11), but bars are cost; the
  two charts share their SVG helper.
- **Unpriced warning:** when any model in the window lacks a price entry, one muted line:
  `N call(s) on <model> have no price — add it to model_prices in settings.yaml.`
- Costs never invent numbers: a missing price means `—`, not 0 (a $0 row is only shown
  when the configured price IS 0, e.g. a free OpenRouter tier).

## 13. Still out of scope

Nothing — as of this revision every previously deferred dashboard item is specced
above.
