# HEIM dashboard redesign: the Braun-inspired monitoring console (Hallmark, full)

Date: 2026-11-01 · Status: **approved by the operator** ("go for it, I like it", after mockup v6) · Branch: `feat/dashboard-redesign`, stacked on `feat/uptime-kuma`.

## Intent (the operator's brief)

Redesign the entire HEIM web dashboard in the spirit of Dieter Rams: a quiet, precise instrument panel whose purpose is immediately clear, making the homelab's condition understandable at a glance. **Do not remove any feature. Only add on top.**

From the brief:

- **Hierarchy.** Every screen answers: what needs attention, are the agents working, and how recent is their information?
- **Palette.** Warm surfaces, dark text, one accent. Red and amber are reserved for meaningful conditions. Healthy states are visually quiet.
- **Typography.** Tabular numerals for metrics; monospace for hostnames, IDs and timestamps; readable secondary text.
- **Geometry.** A strict grid, repeatable spacing, aligned labels, thin separators. Related information is grouped into coherent panels.
- **Density.** Compact rows for comparing agents. Whitespace establishes groups, and useful information stays visible.
- **Honest status.** Healthy, degraded, failed, paused and unknown are distinct. Stale data is shown explicitly, and a colour is always paired with a word.
- **Functional charts.** Small trends with units, time windows and thresholds. Gaps in observations are shown, and each chart answers an operational question.
- **Unobtrusive interaction.** Clear labels, visible focus and selection, restrained motion and predictable navigation. Deeper evidence opens on demand.
- **Two questions kept apart.** *Is the agent functioning?* (heartbeat, last successful check, current task, execution errors, monitored targets) and *what is it reporting?* (affected infrastructure, finding, severity, observation time, supporting evidence).
- **AI output is labelled by kind.** Observations, interpretations, proposed actions and completed actions are distinguished. A concise finding links to the metrics or logs behind it.

## The direction: the operator's console concept

The operator supplied a concept image ("Braun-inspired Heim homelab monitoring console") and approved mockup v6, which reproduces it. **The approved mockup is `.hallmark/mockup/overview.html` (light) and `overview-dark.html` (gitignored, local).** It is the reference for the shell, the components and the overview; later pages reuse its components. Earlier iterations (graphite, teak cheeks and lid, patterned lamps, flat membrane keys, selector-knob lamps) are superseded; `overview-v5-knobs.html` is kept locally for comparison only.

What the concept is, in words:

- **A warm grey ground** with off-white panels that sit on it with a soft 1 px shadow; brown-black ink.
- **Braun orange is the signal:** the logo's lamp, the engaged nav item's lamp, the engaged segment of a switch, the primary button, the flagged row's bar, the monitoring-gap line. Lamps use the vivid orange; text and key faces use a deeper orange that passes 4.5:1.
- **Lamps are bezelled discs.** A lamp is a 14 px disc with a highlight and a two-ring bezel (panel, then hairline). Its colour is the state: red critical/failed, amber warning/degraded/overdue, blue-grey healthy, orange needs you, grey off/paused/unknown, a hollow ring running. The word always sits beside it.
- **Engraved labels:** mono, caps, tracked (`.label`): card titles, table heads, rail group names, the brand line, the task-type line in Needs you, and the page footer.
- **Display type is heavy and tight:** the page title and panel titles at weight 800 with negative tracking; big figures at 36–40 px, tabular. Three weights only: 400, 600, 800.
- **Segmented switches** (`.seg`): a recessed tray with one lifted, lit segment (a small orange lamp before its label).
- **Instrument cards** with a dot grille in the top-right corner (a 3 × 7 dot grid, decorative, part of the concept).
- **The rail** is grouped: Workspace (Overview, Agents, Investigations, Incidents), Infrastructure (Hosts, Metrics, Security), Insights (Findings, Recommendations, Costs); every item has a lamp (orange when current) and some carry a count. The footer holds the daemon's **Connected / Synced n min ago** line and the **Appearance** switch (the theme toggle).
- **Arrows on action links** ("View incidents →") and **middle dots** in meta strings ("4 hosts · 17:39 CET", "HTTP check · port 5678") are part of the concept and stay.
- **No woodgrain**, no emoji, no symbol glyphs as status.

### Hallmark rulings (the operator's concept beats the Floor)

Recorded so nobody "fixes" them: tracked mono caps labels (Floor 67, Reflex 64), the task-type label above each Needs-you heading (Floor 54), arrows glued to action links (Floor 63) and middle-dot meta strings (Floor 63) are **deliberate**. Everything else in the Floor binds: tokens for every colour and font, `overflow-x: clip`, `:focus-visible` at 3:1 or better, reduced-motion fallback, no emoji icons, contrast 4.5:1 on text and 3:1 on marks, the 4 px spacing scale, three font weights.

### Decisions made with the operator (2026-11-01, in order)

1. Braun warm grey ground, not cream (first mockup).
2. Heartbeats are added: the daemon records every scheduled run, success or error.
3. `puppeteer-core` installed globally for Hallmark's render tier.
4. Logo B: lower-case "heim" in geometric arches, the i's dot a lamp. Kept through every iteration; now ink-coloured with an orange dot.
5. No emojis; the theme toggle is a word.
6. The DR01 palette, teak and knob lamps were tried and **superseded** by the console concept (decision 7).
7. **The console concept** (this document). Deeper orange for text and keys (contrast), "H 01" in Braun's own model-number style (a space, not a dash), our real seven agents in the table, system fonts (a self-hosted display face is a later option), Appearance where the concept has Settings.

### Defaults stated to the operator, not objected to

- **Favicon:** `static/logo.svg` keeps its path (a test pins it). Its contents become the compact mark: a lower-case h in off-white on an ink tile, with the orange lamp at its shoulder.
- **Scope:** the dashboard only. The emails are n8n-faithful ports and are frozen; Telegram is unchanged.
- **Dark mode:** the light/dark/auto toggle stays, with the anthracite dark palette from the mockup. Transcript terminals stay dark in both modes.
- **Agent rows:** Alert poller, Threshold watch, Uptime monitor, Investigator, Daily analysis, Security audit, Backup verifier.
- **Labelling an investigation:** tool steps are observations; `## Summary`, `## Root cause` and `## Confidence` are the interpretation; `## Remediation` is the proposed actions; the operator's approval, outcome, mute and verdict are the completed actions. The agent is read-only and takes none.

## Hallmark picks

- **Redesign:** full depth, app scope. Routes: `/`, `/agents` (new), `/agents/{key}` (new), `/investigations`, `/investigations/{id}`, `/incidents`, `/findings`, `/security`, `/recommendations`, `/metrics`, `/costs`, `/hosts`, and the error page.
- **Before:** Floor 199 FAIL · Reflex 89 · WARN 36 (`.hallmark/before.*`, captured against the seeded demo DB: `.hallmark/seed_demo.py`, `.hallmark/demo.sh`).
- **Keeps:** every route, form, field, button, `hx-*` attribute and class hook a test reads; the theme toggle with its no-JavaScript path (`<a class="btn themetoggle">`, now reading `Appearance · Light`); the logo hooks (`class="spark"` on the mark, `aria-label="HEIM"`, the hidden `HEIM` word, `/static/logo.svg`); the dark transcript terminals; every figure the screens show.
- **Idea:** HEIM read like a calibrated instrument. Every agent is a channel on one front panel, read at a glance, and nothing lights up unless it needs a hand.
- **Signature:** the Agents panel. One row per agent, with a strip of its last 24 runs (filled, red for failed, amber for missed, hollow for the slot not yet received), so a missed run is visible as a hole.
- **Chrome:** the grouped rail with lamps and counts; the top bar with the title, the date, "n hosts · HH:MM TZ" and the window switch.
- **States:** loading (the htmx-polled rows), empty, error (a failed metrics fetch, an unreachable source), full. Stale ("Overdue") and unknown ("No data yet") are first-class.
- **Files:** edit `static/heim.css`, `static/logo.svg`, `templates/base.html`, all page templates and partials, `dashboard/app.py`, `dashboard/format.py`, `incidents/store.py`, `daemon.py`, `pipelines/poller.py`, `docs/design/dashboard-ui.md`, `README.md`, `AGENTS.md`; create `design.md`, `src/heim/agents.py`, `templates/agents.html`, `templates/agent.html`, the new tests; delete none.
- **Tests changed (rulings):**
  1. `tests/test_light_mode.py::test_css_has_light_tokens_and_no_stray_dark_hexes`: `#B05E1A` (the old light ember) becomes `#1F1A15`, the new light ink.
  2. `tests/test_light_mode.py::test_toggle_form_cycles_auto_light_dark_and_works_without_js`: `>☀<`, `>☾<`, `>◐<` become `>Light<`, `>Dark<`, `>Auto<`. The cycle, the no-`hx-` check and both aria-label asserts stay.
  3. **Presentation pins:** assertions that pin only the old presentation move to the new wording while what they check stays: caps button labels (`RE-RUN` → `Re-run`, `INVESTIGATE NOW` → `Investigate now`, `MARK FALSE POSITIVE` → `Mark false positive`, `UNMUTE` → `Unmute`, `LOAD 50 MORE` → `Load 50 more`, `✓ CONFIRM` → `Confirm`, `✗ FALSE POSITIVE` → `False positive`), the emoji (`🔒` → `Locked`, `💡 …` → `Suggestion: …`), the pill glyph inside `.dot` (now empty) and the `●` before "Nothing needs attention". **Middle-dot pins are not touched**: the concept keeps them. The complete list is the plan's **Presentation pins** table.

## The system

Tokens live in `static/heim.css` (one stylesheet, no build step; the tests read it). The existing token names are kept where they exist and new ones are added. `:root` holds the dark values (the existing convention), `[data-theme="light"]` and its `prefers-color-scheme` mirror hold the light overrides, declared identically.

### Surfaces and ink

| Role | Token | Light | Dark (`:root`) |
|---|---|---|---|
| ground | `--bg` | `#E6E2DA` | `#1C1916` |
| panel | `--panel` | `#F4F2EC` | `#262220` |
| recessed / tray / hover | `--raised` | `#DDD8CE` | `#2F2A26` |
| hairline | `--line` | `#CBC4B9` | `#3D3733` |
| flagged row | `--flag-bg` | `#F7E6D3` | `#3A2B1E` |
| ink | `--ink` | `#1F1A15` | `#EFEBE4` |
| secondary | `--ink-2` | `#57514A` (7:1) | `#C3BBB0` |
| labels, faint | `--ink-3` | `#6B6459` (5.2:1 on panel) | `#A79E92` (6:1) |
| lamp off | `--lamp-off`, `--lamp-off-hi` | `#8E9499`, `#B7BCC0` | `#4A433E`, `#5E5650` |
| grille dots | `--grille` | `#B8B1A6` | `#4A433E` |
| shadow, highlight | `--shade`, `--glint` | `rgb(31 26 21 / 0.14)`, `rgb(255 255 255 / 0.85)` | `rgb(0 0 0 / 0.45)`, `rgb(255 255 255 / 0.06)` |
| orange for text and key faces | `--signal-ink`, `--signal-edge`, `--on-signal` | `#BE3F0D`, `#A8360A`, `#FFFFFF` | `#F4722F`, `#B8450F`, `#1C1916` |

### Mode-invariant (declared in `:root` only; a test checks `--ok:` is absent from the light block)

| Role | Token | Value |
|---|---|---|
| signal lamp, engaged segment, flagged bar | `--signal`, `--signal-hi` | `#E8541E`, `#F8713A` |
| critical / failed | `--crit`, `--crit-hi` | `#D42B1F`, `#F08274` |
| warning / degraded / overdue / missed | `--warn`, `--warn-hi` | `#C9961C`, `#EFCB6A` |
| healthy | `--ok`, `--ok-hi` | `#9FB0BA`, `#D3DDE2` |
| terminal islands | `--term-bg`, `--term-ink`, `--term-ember` | `#1B1917`, `#E9E2D4`, `#E88C3A` (pinned by tests; declared in the light block too, as today) |

### Lamps

`.lamp` (and the existing `.dot` inside `.pill`, `.sev` and `.verdict`): 14 px, `border-radius: 50%`, `background: radial-gradient(circle at 35% 30%, <hi>, <colour> 65%)`, `box-shadow: 0 0 0 2px var(--panel), 0 0 0 3px var(--line), inset 0 -1px 1px var(--shade)`. In the rail the first ring is `--bg`.

| Lamp | Meaning | Status classes it serves |
|---|---|---|
| `red` | critical, failed | `st-crit` |
| `amber` | warning, degraded, overdue, missed | `st-warn`, agent `degraded` and `stale` |
| `orange` | needs you (approval) | pending approval, Needs-you approval rows |
| `blue` | healthy, complete, resolved, ok | `st-ok`, agent `healthy` and `idle` |
| (default grey) | off, paused, muted, declined, unknown, n/a | `st-muted`, agent `paused` and `unknown` |
| `ring` | running | `st-running`, agent `running` |
| `st-serious` (needs a human, incomplete) | `amber` lamp | |

Sizes: `.lamp.lg` 32 px (the condition card), `.lamp.sm` 12 px (inside a segment). The word always accompanies the lamp; the lamp is `aria-hidden`.

### Other components

- **Labels** `.label`: `600 11px/1 var(--mono)`, `letter-spacing: 0.14em`, `text-transform: uppercase`, `--ink-3`.
- **Display:** `h1` 40 px / 800 / `-0.03em`; panel `h2` 22 px / 800 / `-0.02em`; `.big` figures 36 px / 800, tabular, `white-space: nowrap`.
- **Body:** 14 px / 1.45, system sans. Mono for hosts, ids, fingerprints, commands, timestamps and the date line.
- **Panels and cards:** `--panel`, 1 px `--line`, radius 8 px, `box-shadow: inset 0 1px 0 var(--glint), 0 1px 2px var(--shade)`. Cards reserve 48 px on the right for the grille.
- **Buttons** `.btn`: 36 px, radius 6 px, panel face with a hairline and the same soft shadow; `.btn.primary` (and the legacy `.btn.ember` hook, aliased) is `--signal-ink` with `--on-signal` text and a `--signal-edge` border. Hover tints to `--raised` / `--signal-edge`; active nudges 1 px; disabled at 0.5 opacity.
- **Segmented switch** `.seg`: tray `--raised` with a hairline, 4 px padding; segments 32 px; the engaged `.on` segment is lifted (`--panel`, hairline ring, soft shadow) and carries a `.lamp.sm.orange`. Plain links (`?window=`, `?agents=`), so it works without JavaScript.
- **Tables** `.tbl`: `.label` heads, 12 px vertical padding, hairline rows; a flagged row (`tr.flag`) is `--flag-bg` with a 4 px `--signal` left bar.
- **Run strip** `.runs`: 10 px dots, 8 px apart: `--ink` success, `--crit` failed, `--warn` missed, hollow (2 px `--ink` ring) for the latest slot not received. A key follows the table: Success · Failed · Missed.
- **Grille** `.grille`: `radial-gradient(circle, var(--grille) 1.6px, transparent 2.1px) 0 0 / 10px 10px`, 30 × 70 px, top-right of a card.
- **Focus:** `outline: 2px solid var(--ink); outline-offset: 2px` (the orange ring failed 3:1 on the ground).
- **Motion:** `transform` and `opacity` only, `--dur-micro` 120 ms; everything stops under reduced motion.
- **Spacing:** 4 px steps. Rail 232 px. Container 1440 px. Phones (`max-width: 60rem`): the rail becomes a wrapped row of lamp-chips above the page, cards stack, tables restack into rows, nothing scrolls sideways at 375 or 320.

## The agent model (backend, added on top)

**`agent_runs`** is a new table: `id, agent, started_at, finished_at, ok, error, detail_json`, indexed on `(agent, started_at)`.

- **Who writes it:** the daemon's job wrappers, after every run. CLI one-off runs write nothing: the table asserts that the daemon is functioning, the same reasoning as the dead-man ping. The dashboard never writes it.
- **Retention:** pruned by `store.prune` after 14 days (`AGENT_RUNS_RETENTION_DAYS`).

| Agent key | Name | Recorded from | Error when | Cadence / stale-after |
|---|---|---|---|---|
| `alert_poller` | Alert poller | `_poll_job`, the alert half's counters | the half aborted, e.g. Prometheus unreachable | 5 min / 15 min |
| `thresholds` | Threshold watch | `_poll_job`, the threshold counters | no usable samples, or the half raised | 5 min / 15 min; paused when `threshold_detection` is false |
| `uptime` | Uptime monitor | `_poll_job`, the uptime counters | `uptime_unreachable`, or the half raised | 5 min / 15 min; paused when `uptime_kuma.url` is empty |
| `daily` | Daily analysis | `_daily_job` | it raised | twice daily (from `schedules.daily`); stale once the next run is over 1 h late |
| `security` | Security audit | `_security_audit_job` | it raised | weekly; stale after 8 days; paused when the schedule is empty |
| `backup` | Backup verifier | `_backup_job` | the backup or the prune failed | daily 03:30; stale after 26 h |
| `investigator` | Investigator | **not recorded**; derived from `investigations` | the last finished run was failed or incomplete | on demand; never stale; running while one runs |

**Status** (pure, `src/heim/agents.py`) is exactly one of: **healthy** (last run ok and fresh) · **degraded** (last ok, the one before errored) · **failed** (last run errored) · **paused** (disabled in config) · **unknown** (no runs yet; the word is "No data yet") · **stale** (last ok but older than stale-after; the word is "Overdue") · **running** (investigator only) · **idle** (investigator, nothing running, last outcome fine).

**Coverage** comes from config and the latest run's `detail_json`: hosts, catalog query count, monitor and report-only counts, check count, investigable hosts.

**Run strip:** the last 24 runs. For agents on a cadence, a stretch longer than twice the cadence between two runs inserts a **missed** tick; when the newest run is older than the cadence, the strip ends with a hollow **not received** tick.

**Overall condition** (`overall_condition`): **unknown** when any un-paused watcher (`alert_poller`, `thresholds`, `uptime`) is stale or unknown; else **critical** when any open incident is critical; else **degraded** when any is a warning or any agent is failed or degraded; else **normal**. It also returns the counts the Infrastructure card shows: critical open, warning open.

**Window** (`?window=live|24h|7d`, default `live`): scopes the run strips and the Observations ruler. `live` is the last 24 runs; `24h` and `7d` bucket the window into 24 equal slots, each slot a dot: red if any run in it failed, amber if the slot has no run on a cadenced agent, filled if ok, hollow for the newest slot still open. Nothing else on the page changes with the window; open incidents are what is open now.

**Workflow** (`workflow_for(incident, investigations)`, pure): what HEIM is doing about a finding, shown as a title and a sub-line: *Investigating / Agent is checking · investigation N* (a running one on its fingerprint), *Awaiting approval / investigation N* (pending), *Open / Needs attention* (investigable host, no investigation), *Open / Report-only target* (an `[uptime]` incident on a non-investigable address), *Open / Monitoring threshold* (a `[metric]` incident), *Open / Alert rule* (an `[alert]` incident), *Needs a human / investigation N*.

## Page by page (every existing feature stays)

- **Overview `/`:**
  1. **Top bar:** `h1` Overview, the date in the configured timezone ("Sunday, 1 November"), "n hosts · HH:MM TZ", the window switch Live / 24 h / 7 d.
  2. **Four cards:** **Infrastructure** (big lamp in the condition's colour, the count of critical open incidents as a two-digit figure, the condition word, "n warnings open"); **Agent coverage** ("n / 7 Reporting", one disc per agent, hollow when not reporting, a foot line naming the agent that isn't); **Observations** ("n min Since last sync", a tick ruler of the window's polls with misses marked red, "Prometheus · Uptime Kuma"); **Requires you** (the count of items in Needs you, "n approvals · n physical checks").
  3. **Needs attention** (left, wide): "n findings", "View incidents →"; a table Finding (lamp + severity word; title; sub-line), Host (mono), Workflow, Age. Ordered: critical incidents, then warnings, oldest first within a group; suppressed excluded; the existing needs-attention investigation rows (incomplete, failed, needs human) are listed here too with their re-run form.
  4. **Needs you** (right): one task per `pending_approval` investigation (orange lamp, label "Approval", title from the brief's first finding, mono detail, "Review the proposed diagnostic scope.", primary button "Review investigation →" to the detail page where Approve/Decline live) and per `needs_human` investigation (amber lamp, label "Physical check" when the report's remediation names a physical action, else "Needs a human"; "View evidence →"). Empty state: "Nothing needs you. The agents are handling it."
  5. **Agents** (full width): the switch All n / Running n / Attention n (`?agents=`), the table Agent / scope, Execution state (lamp + word), Last success, Last 24 runs (the strip), a chevron linking to `/agents/{key}`; a stale or failed agent is a flagged row; below the table one **monitoring-gap line** per flagged agent ("Monitoring gap: latest backup result not received." with "Review backup runs →" to `/agents/backup`), then the run key.
  6. **Every existing overview block below, restyled:** the five figures, the health card with its per-host strip, latest runs, tool usage with tooling feedback, token usage, recent investigations, recent findings.
  7. **Footer line:** "HEIM / H 01" and the build or version.
- **Agents `/agents`** (new): the same Agents panel, full page, with the switch; each row links to its detail.
- **Agent `/agents/{key}`** (new): the agent's state, coverage, cadence, last success and error, the run strip, the last 24 runs as a table (time, result, duration, what happened) and evidence links (`alert_poller`, `thresholds` → `/incidents`; `uptime` → `/incidents`; `daily` → `/findings`; `investigator` → `/investigations`; `security` → `/security`; `backup` → the last backup file name). 404 for an unknown key.
- **Rail counts:** Agents = 7 (the agent count), Investigations = running + pending approval, Incidents = open (not suppressed), Hosts = configured hosts. Supplied by the shared `page()` helper so every page shows them.
- **Investigations and an investigation:** the list keeps its filters, ghost rows and "Load 50 more"; the detail page sorts the report into **Observations** (the transcript, dark terminal islands kept), **Interpretation**, **Proposed actions** and **Completed actions**; the full raw report stays available; every existing block (brief, replay-of, waiting age, transcript JSON, tooling feedback, actions) stays.
- **Incidents and hosts:** restyled on the system. Ownership (Alert, Metric, Uptime, Daily analysis) is a word; the lock emoji becomes the word "Locked" (hook kept). Every action stays.
- **Findings, security and recommendations:** every finding links to its evidence (the metric on `/metrics#q-<qid>`, the incident, its investigation). Verdicts, mutes and checkboxes stay.
- **Metrics and costs:** each chart states the question it answers, its unit, its window and its thresholds, and draws gaps where observations are missing.
- **Error page, flash messages, phones:** on the system; no sideways scrolling at 375 or 320.

## Constraints

- **AGENTS.md.** Pure logic is tested, I/O stays at the edges, no real IP or URL is committed (screenshots stay in the gitignored `.hallmark/`), and the dashboard writes only through its existing action allow-list (`_ACTION_HELPERS`). It **never writes** `agent_runs`.
- **No webfonts, no JS framework, no chart library.** htmx only. (A self-hosted display face is a possible later addition, not part of this work.)
- **Hallmark:** the Floor binds except for the four rulings above. `sloplint --scope app --render` per page; `--kept` against the before record at the end; the fresh-context finish review.
- **Tests:** the existing suite stays green, apart from the ruled changes above and the known local-settings failure (`tests/test_observability.py::test_both_settings_yamls_document_the_new_knobs`).
