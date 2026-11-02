# HEIM Dashboard Redesign (the Braun-inspired console) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild every HEIM dashboard screen as the operator's Braun-inspired monitoring console, without removing anything, and add heartbeats so the overview can answer: what needs attention, are the agents working, and how fresh is their information.

**Architecture:**
- A new `agent_runs` table (written only by the daemon's job wrappers) and a pure `src/heim/agents.py` turn job history into honest per-agent status, coverage, run strips and the overall condition.
- One stylesheet, `static/heim.css`, carries the system: the existing token names plus the console's new ones, under the Hallmark stamp. `design.md` locks the system for every page task.
- Pages are recomposed in their Jinja templates inside a new grouped rail shell, keeping every route, form, `hx-*` attribute and test hook. Two routes are added: `/agents` and `/agents/{key}`.

**Tech Stack:** Python 3.13, FastAPI + Jinja + vendored htmx, SQLite (`IncidentStore`), pytest, Hallmark (`~/.claude/skills/hallmark`: `sloplint.mjs`, render tier on puppeteer-core plus local Chrome).

**Spec:** `docs/superpowers/specs/2026-11-01-dashboard-redesign-design.md`. Read it first: the brief, the approved direction, the rulings, the system tables, the agent model and the page-by-page list.

**Approved mockup:** `.hallmark/mockup/overview.html` and `overview-dark.html` (gitignored, local). It is the visual reference for the shell, the components and the overview. **Copy its CSS for the shell and components rather than re-deriving them**; its demo data is mockup-only.

Work on branch `feat/dashboard-redesign` (already created, stacked on `feat/uptime-kuma`). Commit the spec and this plan with Task 1.

## Global Constraints

- **Keep everything.** No route, form, field, button, link, `hx-*` attribute, `id`, `name` or class a test reads is removed or renamed. Restyle a hook, never delete it. The final task's `sloplint --kept` must report 0 `FAIL kept`.
- **Tests.**
  - The existing suite stays green, apart from the known pre-existing failure `tests/test_observability.py::test_both_settings_yamls_document_the_new_knobs` (it reads a local gitignored file).
  - **Ruled test changes, and only these:**
    1. `tests/test_light_mode.py::test_css_has_light_tokens_and_no_stray_dark_hexes`: `"#B05E1A" in css` becomes `"#1F1A15" in css`, the new light ink (Task 2).
    2. `tests/test_light_mode.py::test_toggle_form_cycles_auto_light_dark_and_works_without_js`: the three glyph asserts become `">Light<" in toggle("light")[1]`, `">Dark<" in toggle("dark")[1]`, `">Auto<" in toggle(None)[1]`, with the comment `# the toggle says its state as a word (operator ruling 2026-11-01: no emoji)`. The cycle asserts, the no-`hx-` check and both aria-label asserts stay byte-identical (Task 2).
    3. **Presentation pins** (table below): an assertion that pins *only* the old presentation (a caps label, an emoji, a glyph) moves to the new wording; what it checks (presence, count, order, absence, the link) stays. Each row is owned by the task that changes that markup; change the pin in the same commit as the markup, so the suite is green after every task.

    **Middle-dot strings stay** (the concept uses them), so no `·` pin changes. Never edit any other existing test to make the redesign pass. If a task meets a pin not in the table, stop and report it rather than editing it.
- **One stylesheet, no build.** `src/heim/dashboard/static/heim.css` holds every token. No webfonts, no JS framework, no chart library. htmx only.
- **Tokens.** `:root` holds the dark values, `[data-theme="light"]` and the `prefers-color-scheme: light` mirror hold the light overrides, declared identically (a test compares them). Values from the spec's tables, verbatim:

  | Token | Light | Dark |
  |---|---|---|
  | `--bg` | `#E6E2DA` | `#1C1916` |
  | `--panel` | `#F4F2EC` | `#262220` |
  | `--raised` | `#DDD8CE` | `#2F2A26` |
  | `--line` | `#CBC4B9` | `#3D3733` |
  | `--flag-bg` | `#F7E6D3` | `#3A2B1E` |
  | `--ink` | `#1F1A15` | `#EFEBE4` |
  | `--ink-2` | `#57514A` | `#C3BBB0` |
  | `--ink-3` | `#6B6459` | `#A79E92` |
  | `--lamp-off` / `--lamp-off-hi` | `#8E9499` / `#B7BCC0` | `#4A433E` / `#5E5650` |
  | `--grille` | `#B8B1A6` | `#4A433E` |
  | `--shade` / `--glint` | `rgb(31 26 21 / 0.14)` / `rgb(255 255 255 / 0.85)` | `rgb(0 0 0 / 0.45)` / `rgb(255 255 255 / 0.06)` |
  | `--signal-ink` / `--signal-edge` / `--on-signal` | `#BE3F0D` / `#A8360A` / `#FFFFFF` | `#F4722F` / `#B8450F` / `#1C1916` |
  | `--term-bg` / `--term-ink` / `--term-ember` | `#1B1917` / `#E9E2D4` / `#E88C3A` (pinned, in the light block as today) | same |

  **Mode-invariant, in `:root` only** (a test checks `--ok:` is absent from the light block): `--signal #E8541E`, `--signal-hi #F8713A`, `--crit #D42B1F`, `--crit-hi #F08274`, `--warn #C9961C`, `--warn-hi #EFCB6A`, `--ok #9FB0BA`, `--ok-hi #D3DDE2`. The tool palette (`--tool-*`) and host colours stay where they are.
- **Lamps.** `.lamp`, and the existing empty `.dot` span inside `.pill`, `.sev` and `.verdict`: 14 px disc, `radial-gradient(circle at 35% 30%, <hi>, <colour> 65%)`, `box-shadow: 0 0 0 2px var(--panel), 0 0 0 3px var(--line), inset 0 -1px 1px var(--shade)`; in the rail the first ring is `--bg`. Colour by class: `red` (`st-crit`), `amber` (`st-warn`, `st-serious`, agent degraded/stale), `orange` (needs you), `blue` (`st-ok`), default grey (`st-muted`, paused, unknown), `ring` (`st-running`: transparent, `inset 0 0 0 2px var(--ink)`). `.lamp.lg` 32 px, `.lamp.sm` 12 px. The lamp is `aria-hidden`; the word is always beside it. No glyph inside a `.dot` ever again.
- **Labels** `.label`: `600 11px/1 var(--mono)`, `letter-spacing: 0.14em`, `text-transform: uppercase`, `--ink-3`. Used for card titles, table heads, rail group names, the brand line, the Needs-you task type and the footer. **Operator ruling:** this departs from Hallmark Floor 67 / Reflex 64 on purpose; so do the task-type label above a Needs-you heading (54), arrows on action links (63) and middle-dot meta strings (63). Everything else in the Floor binds.
- **Type.** System sans; three weights only: 400, 600, 800. `h1` 40 px / 800 / `-0.03em`; panel `h2` 22 px / 800 / `-0.02em`; `.big` 36 px / 800, tabular, nowrap; body 14 px / 1.45. Mono (`--mono`) for hosts, ids, fingerprints, commands, timestamps, the date line. `text-wrap: balance` on `h1, h2, h3`.
- **Components** (copy from the mockup): panels and cards (radius 8 px, hairline, `inset 0 1px 0 var(--glint), 0 1px 2px var(--shade)`; cards reserve `padding-right: 48px` for `.grille`), `.btn` (36 px, radius 6 px) and `.btn.primary` (= the legacy `.btn.ember` hook, aliased in CSS: `--signal-ink` face, `--on-signal` text, `--signal-edge` border), `.seg` segmented switch (plain links, engaged `.on` segment lifted with a `.lamp.sm.orange`, `aria-current="true"`), `.tbl` (label heads, 12 px rows, `tr.flag` with `--flag-bg` and a 4 px `--signal` left bar), `.runs` strip (10 px dots: `--ink` ok, `--crit` fail, `--warn` miss, hollow `open`), `.grille`, `.gap` line with `.bang`.
- **Focus:** `:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }`. **Motion:** `transform`/`opacity` only, `--dur-micro: 120ms`; `prefers-reduced-motion: reduce` stops everything. **Spacing:** 4 px steps. **Rail:** 232 px fixed; on phones (`max-width: 60rem`) a wrapped row of lamp-chips above the page. **Container** 1440 px.
- **Hallmark Floor** (every task, apart from the four rulings): every colour and font through a token; `overflow-x: clip` on `html, body`; `:focus-visible` on every interactive element at 3:1 or better; no emoji as icons and no symbol glyph as a status (`💡 🔒 👍 ☀ ☾ ◐ ● ○ ◌ ◐ ◷ ✓ ✗ ✕ ⚠ ✳ ▲ ◆ ‖` go, replaced by words and lamps; the `→` on an action link and the `›` chevron on an agent row are allowed); contrast 4.5:1 on text, 3:1 on marks; no invented figures.
- **The stamp.** `heim.css` line 1 is the Hallmark stamp (Task 2 writes it; copy the mockup's and set `redesign: full`), plus the critique line.
- **Agent recording is daemon-only.** The dashboard never writes `agent_runs` (not in `_ACTION_HELPERS`); CLI one-offs don't write it either. `AGENT_RUNS_RETENTION_DAYS = 14`.
- **Public repo.** No real IP, URL or key in code, tests or docs. Screenshots stay in the gitignored `.hallmark/`. `.hallmark/seed_demo.py` is local tooling: edit it, never commit it.
- **Visual checks per page task.** `.hallmark/demo.sh reseed && .hallmark/demo.sh start` serves the seeded demo on `http://127.0.0.1:8399`. Then `node ~/.claude/skills/hallmark/scripts/sloplint.mjs <changed templates + heim.css> --genre modern-minimal --scope app --render --url http://127.0.0.1:8399/<route>` in **both** themes (`?theme=light`, `?theme=dark` set the cookie). Fix every FAIL except the four ruled ones (54, 63 arrows, 63 middle dots, 67/64 labels). Look at the 1440 and 375 screenshots in `.hallmark/` before reporting.

### Presentation pins

| Task | Test (line at plan time) | Old | New |
|---|---|---|---|
| 2 | `test_metrics_page.py:159` | `…<span class="dot" aria-hidden="true">·</span>n/a` | `…<span class="dot" aria-hidden="true"></span>n/a` |
| 2 | `test_dashboard_actions.py:211, 365, 481` | `INVESTIGATE NOW`, `MARK FALSE POSITIVE`, `UNMUTE` | `Investigate now`, `Mark false positive`, `Unmute` |
| 2 | `test_dashboard_actions.py:249, 498, 503`; `test_needs_attention.py:198` | `RE-RUN` | `Re-run` |
| 2 | `test_dashboard_actions.py:515, 523`; `test_findings_table.py:137, 154` | `✓ CONFIRM`, `✗ FALSE POSITIVE` | `>Confirm<`, `>False positive<` (count the exact `>Confirm<` so "confirmed" elsewhere never matches; if the `m.act` macro wraps the label, pin that exact markup) |
| 2 | `test_pagination.py` (every `LOAD 50 MORE`) | `LOAD 50 MORE` | `Load 50 more` |
| 2 | `test_dashboard_actions.py:478, 484` | `UNMUTE` | `Unmute` |
| 2 | `test_dashboard_actions.py:496, 504` | `APPROVE`, `DECLINE` | `Approve`, `Decline` |
| 2 | `test_dashboard_actions.py:315` | `"CONFIRM"` | `">Confirm<"` |
| 2 | `test_metrics_page.py:296` (`test_nav_has_metrics_between_findings_and_hosts`) | the flat order findings < metrics < hosts | the grouped rail's Infrastructure order: `hosts < metrics < security`; presence checks unchanged |
| 2 | `test_dashboard_actions.py:365` | `"UNMUTE" not in r.text` | `">Unmute<" not in r.text` (the flash sentence "Unmuted — …" would otherwise match the bare word) |
| 6 | `test_dashboard.py:307, 411` | `"⛔ blocked"` | `">blocked<"` (the badge becomes a red lamp plus the word: `<span class="st-crit"><span class="dot" aria-hidden="true"></span>blocked</span>`); `⛔` joins `RETIRED` in `tests/test_dashboard_system.py` in the same commit, and the overview's tool-usage blocked count (`overview.html:205`) drops its `⛔` for a red lamp |
| 2 | `test_dashboard.py:494` (the `heim.css` byte cap) | `<= 21_248` | `<= 32_768`, raised once for the whole redesign, with a docstring line naming the raise; Tasks 3–9 must fit under it |
| 2 | `test_needs_attention.py:274` | `<span aria-hidden="true">●</span> Nothing needs attention.` | `<span class="lamp blue" aria-hidden="true"></span> Nothing needs attention.` |
| 2 | `test_tool_feedback.py:278, 280, 294` | `💡 allow du…`, `💡 general: logs: …`, `"💡" not in html` | `Suggestion: allow du…`, `Suggestion, general: logs: …`, `"Suggestion" not in html` |
| 2 | `test_dashboard.py:439` | `"🔒" in html` | `"Locked" in html` |
| 3 | `test_needs_attention.py:197, 210, 225, 237, 262` | `"needs attention"` in `html.index` / `card.index` / `many.index` slices | `"Needs attention"` (the panel title becomes a display heading in sentence case) |
| 3 | `test_needs_attention.py:204` | `card health` before `needs attention` | `html.index("Needs attention") < html.index("card health") < html.index("latest runs")` (the concept puts Needs attention first and the health card among the existing blocks below) |

**Heading case (pre-flight ruling 7):** the tests slice the overview on lowercase caption text (`html.index("latest runs")`, `"recent investigations"`, `"tool usage"`, `"triggered by"`, `"transcript · "`). Those secondary blocks keep their **lowercase DOM caption text**, rendered as `.label` mono caps by CSS (the concept's engraved-label style), so every such slice holds unchanged. Only the concept's display headings ("Needs attention", "Needs you", "Agents", page titles) are sentence case in the DOM.

**Not pins, keep as they are:** every `·` string (`transcript · 3 steps`, `queued · waiting for daemon`, `daily · `, `showing findings 1–50 · newest first`, `investigator · claude-sonnet-4-6`, `(1 crit · 1 warn)`, `html.count(" · ~") == 2`), arrows inside data (`128k → 4.2k`), `×7`, the `▲ 13.3%` change markers (data, not status), em dashes in flash sentences, `title=` tooltips, the agent brief's `DETECTED FINDINGS` and the audit report's `EVIDENCE EXCERPTS` (content), `fmt.status_pill`'s returned `icon` field.

## Review Focus

1. **A dead or silent daemon.** No `agent_runs` newer than stale-after makes every watcher **Overdue**, the condition **unknown** (never "normal"), the Infrastructure lamp grey, and the rail footer "Daemon quiet". An agent with no rows is **No data yet**, never Healthy. (Tasks 1, 3.)
2. **No JavaScript.** The window switch, the agents filter, the theme toggle and every action form work as plain links and forms; htmx only enhances. (Tasks 3, 5.)
3. **Phones at 375 and 320 px.** No sideways scrolling on any route; tables keep the row-naming column visible. (Each page task's render check, Task 10.)
4. **Dark mode parity.** Every component reads tokens only (`test_components_read_theme_tokens_only` covers `heim.css`); lamps and the orange stay legible in both modes (`--signal-ink` differs per mode for that reason). (Task 2.)
5. **Keyboard.** Every control shows its focus ring instantly at 3:1 or better; the engaged segment and the current nav item carry `aria-current`. (Tasks 2, 3.)
6. **Honest counts.** The rail counts, the card figures and the Needs-you count come from the same store reads as the lists they summarise; they never disagree with the rows below. (Task 3 test.)

---

### Task 1: Heartbeats: `agent_runs`, the pure agent model, daemon recording

**Files:**
- Modify: `src/heim/incidents/store.py` (schema string: new table + index; methods next to `threshold_streaks()`; `prune()`)
- Create: `src/heim/agents.py` (pure: no I/O, no store access)
- Modify: `src/heim/pipelines/poller.py` (`run_poll`: add `threshold_failed` and `uptime_failed` booleans to the summary when those halves raise)
- Modify: `src/heim/daemon.py` (`_poll_job`, `_daily_job`, `_security_audit_job`, `_backup_job`, plus a `_record_agent_run` helper)
- Test: `tests/test_agents.py` (new)
- Commit with this task: `docs/superpowers/specs/2026-11-01-dashboard-redesign-design.md`, `docs/superpowers/plans/2026-11-01-dashboard-redesign.md`

**Interfaces:**
- Produces, in `store.py`:
  - schema `agent_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT '', ok INTEGER NOT NULL DEFAULT 1, error TEXT NOT NULL DEFAULT '', detail_json TEXT NOT NULL DEFAULT '{}')`
  - `CREATE INDEX IF NOT EXISTS idx_agent_runs_agent ON agent_runs (agent, started_at)`
  - `AGENT_RUNS_RETENTION_DAYS = 14`
  - `IncidentStore.record_agent_run(agent: str, started_at: str, finished_at: str, ok: bool, error: str = "", detail: dict | None = None) -> int`
  - `IncidentStore.agent_runs(agent: str, limit: int = 24, since: str | None = None) -> list[dict]`, newest first; each dict has `agent, started_at, finished_at, ok (bool), error, detail (dict)`; `since` (ISO) is an inclusive lower bound on `started_at`, used by the window (Task 5)
  - `IncidentStore.agent_runs_by_agent(limit_per_agent: int = 24, since: str | None = None) -> dict[str, list[dict]]`
  - `prune()` also deletes `agent_runs` whose `started_at` is older than `AGENT_RUNS_RETENTION_DAYS` days, reported in its counts as `agent_runs`
- Produces, in `agents.py`:
  - `AGENT_KEYS = ("alert_poller", "thresholds", "uptime", "investigator", "daily", "security", "backup")`, the table's display order
  - `@dataclass(frozen=True) class AgentSpec: key: str; name: str; cadence_s: int | None; stale_after_s: int | None; paused: bool; scope: str`
  - `agent_specs(cfg, latest_detail: dict[str, dict]) -> list[AgentSpec]`; `cfg` is the loaded `Config`, `latest_detail` maps an agent key to its newest run's `detail`
  - `@dataclass(frozen=True) class AgentStatus: key: str; state: str; word: str; lamp: str; last_run_at: str; last_ok_at: str; last_error: str; last_error_at: str; current: str`, where `lamp` is a `.lamp` colour class
  - `status_of(spec: AgentSpec, runs: list[dict], now_iso: str) -> AgentStatus` (`runs` newest first)
  - `investigator_status(investigations: list[dict], now_iso: str) -> AgentStatus` (newest first, as `store.investigations()` returns)
  - `@dataclass(frozen=True) class Tick: state: str; at: str`, `state` one of `ok`, `fail`, `miss`, `open`
  - `run_strip(runs: list[dict], cadence_s: int | None, now_iso: str, n: int = 24) -> list[Tick]`, oldest to newest, at most `n`
  - `overall_condition(open_incidents: list[dict], statuses: list[AgentStatus]) -> dict` → `{"state": "critical"|"degraded"|"normal"|"unknown", "word": str, "lamp": str, "crit": int, "warn": int, "detail": str}`
- States, words and lamps, exactly:

  | `state` | `word` | `lamp` |
  |---|---|---|
  | `healthy` | Healthy | `blue` |
  | `degraded` | Degraded | `amber` |
  | `failed` | Failed | `red` |
  | `paused` | Paused | `` (grey default) |
  | `unknown` | No data yet | `` |
  | `stale` | Overdue | `amber` |
  | `running` | Running | `ring` |
  | `idle` (investigator: nothing running, last outcome fine) | Idle | `blue` |

- Names: Alert poller, Threshold watch, Uptime monitor, Investigator, Daily analysis, Security audit, Backup verifier.
- Specs: poll agents `cadence_s=300, stale_after_s=900`; `daily`: `cadence_s` is the largest gap between consecutive `schedules.daily` times (wrapping midnight), `stale_after_s = cadence_s + 3600`; `security` `604800 / 691200`; `backup` `86400 / 93600`; `investigator` both `None`; paused: `thresholds` when `settings.threshold_detection` is false, `uptime` when `settings.uptime_kuma.url == ""`, `security` when `settings.schedules.security_audit == ""`.
- Scope strings (middle dots are the concept's separator): `alert_poller` `"Prometheus alerts · {n} hosts"`; `thresholds` `"{n} catalog queries"`; `uptime` `"{monitors} monitors · {report_only} report-only"` or `"Off"`; `investigator` `"{host} · investigation {id}"` while running (the caller passes `latest_detail["investigator"] = {"running_host": str, "running_id": int}`; the dashboard builds it from `store.investigations(status="running")`), else `"investigates {comma-joined investigable hosts}"`; `daily` `"{n} queries · {hosts} hosts"`; `security` `"{n} checks"`; `backup` `"Expected daily at {HH:MM}"` from the backup schedule (03:30 today).
- `run_strip`: a stretch longer than twice the cadence between two consecutive runs inserts one `miss` tick; when the newest run is older than the cadence, append one `open` tick. `fail` for `ok=False`. Agents with `cadence_s=None` never get `miss` or `open`.
- `overall_condition`: **unknown** when any un-paused watcher among `alert_poller`, `thresholds`, `uptime` is `stale` or `unknown` (lamp grey, word "Unknown"); else **critical** when any open incident is critical (lamp `red`); else **degraded** when any is a warning or any agent is failed or degraded (lamp `amber`); else **normal** (lamp `blue`, word "Normal"). `crit`/`warn` count open incidents by severity (`critical`/`crit`, `warning`/`warn`); `detail` is `"{warn} warnings open"` (singular when 1; `"nothing else open"` when 0).

- [ ] **Step 1: Write the failing tests** in `tests/test_agents.py` (the store part uses `IncidentStore(tmp_path / "t.sqlite3")`):
  - `test_record_and_read_agent_runs_newest_first`
  - `test_agent_runs_since_bound_is_inclusive`
  - `test_agent_runs_by_agent_caps_per_agent`
  - `test_prune_drops_agent_runs_older_than_14_days_only`
  - `test_no_runs_is_unknown_not_healthy`
  - `test_fresh_ok_run_is_healthy`
  - `test_ok_after_error_is_degraded`
  - `test_last_error_is_failed_with_message`
  - `test_old_ok_run_is_overdue`: `stale_after_s` + 1 s ago gives `stale` / "Overdue" / `amber`
  - `test_paused_spec_is_paused_whatever_the_runs`
  - `test_run_strip_marks_misses_and_the_open_slot`: runs at 2, 7, 12 and 32 min ago with a 300 s cadence give `ok, miss, ok, ok, ok` (oldest first) and no `open`; runs ending 9 min ago give a trailing `open`
  - `test_investigator_running_idle_and_failed`
  - `test_overall_condition_unknown_when_a_watcher_is_overdue`: an overdue watcher wins over critical incidents
  - `test_overall_condition_critical_degraded_normal_with_counts`
  - `test_specs_paused_flags_and_daily_cadence_from_schedule`: `schedules.daily = ["07:00", "22:00"]` gives `cadence_s == 15 * 3600`
  - Daemon recording, using the rt fixture pattern from `tests/test_thresholds.py` and monkeypatching `daemon.run_poll`:
    - `test_poll_job_records_three_agents`: a summary with `aborted`, `threshold_samples: 0` and `uptime_unreachable: True` gives three rows, all `ok=False`, with messages
    - `test_daily_job_failure_records_error`
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_agents.py -q`. Expected: FAIL (import errors); capture the output.
- [ ] **Step 3: Implement** the store methods, `agents.py`, the `run_poll` flags and the daemon recording.
  - `_record_agent_run(rt, agent, started_at, ok, error="", detail=None)` wraps `rt.store.record_agent_run` in `try`/`except` with `log.exception`: recording is a side channel and must never break a job.
  - `_poll_job` records the three poll agents from `run_poll`'s summary, before the dead-man ping. Paused agents get no row.
  - Error messages are short: `"Prometheus unreachable"`, `"no usable samples"`, `"Uptime Kuma unreachable"`, or `f"{type(exc).__name__}: {exc}"` truncated to 200 characters.
  - `detail` carries the counters the scopes need: hosts, queries, monitors, report_only, checks, backup file name.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_agents.py tests/test_ops.py tests/test_thresholds.py tests/test_uptime_pipeline.py -q`, then the full suite. Expected: PASS, except the known failure.
- [ ] **Step 5: Commit**

```bash
git add src/heim/incidents/store.py src/heim/agents.py src/heim/pipelines/poller.py src/heim/daemon.py tests/test_agents.py docs/superpowers/specs/2026-11-01-dashboard-redesign-design.md docs/superpowers/plans/2026-11-01-dashboard-redesign.md
git commit -m "agents: heartbeats — agent_runs written by the daemon, honest per-agent status"
```

### Task 2: The system, the shell and `design.md`

**Files:**
- Modify: `src/heim/dashboard/static/heim.css`: rewrite the stamp, the token blocks, base rules, the shell (grouped rail, top bar), `.label`, `.lamp`, `.seg`, `.btn`, panels and cards, `.tbl`, `.runs`, `.grille`, `.gap`, and re-skin the shared components the pages already use (`.card`, `.pill`, `.sev`, `.chip`, `.empty`, `.flash`, `.acts`, the terminal islands). Page-specific rules are re-themed here; pages are recomposed in later tasks.
- Modify: `src/heim/dashboard/templates/base.html` (the grouped rail with lamps and counts, the brand block "heim / HOMELAB MONITOR / H 01", the rail footer with the Connected line and the Appearance toggle, the top bar with title, date, "n hosts · HH:MM TZ" and a `{% block switch %}` slot for a page's segmented control), `templates/partials/_macros.html` (`m.pill`, `m.sev`, `m.muted` with an empty `.dot`; new `m.lamp(colour)` and `m.seg(items)`), `templates/partials/_flash.html`
- Modify: `src/heim/dashboard/static/logo.svg` (the compact favicon mark: an ink tile, a lower-case h in off-white, the orange lamp at its shoulder; a standalone SVG may use literal colours)
- Modify: `src/heim/dashboard/app.py`: `NAV` becomes `NAV_GROUPS = [("Workspace", [...]), ("Infrastructure", [...]), ("Insights", [...])]` with the flat `NAV` derived from it (anything reading `NAV` keeps working); `page()` adds `nav_groups`, `rail_counts` (`{"/agents": 7, "/investigations": running + pending_approval, "/incidents": open not suppressed, "/hosts": len(cfg.hosts)}`, each omitted on a store error) and `date_line` (`f"{now:%A}, {now.day} {now:%B}"`); `_daemon_chip` reads the newest poll `agent_runs` row (`alert_poller`, `thresholds`, `uptime`) and falls back to the `runs` table when there is none, returning `{"ok", "label": "Connected"|"Daemon quiet"|"No heartbeat yet", "when": "Synced 2 min ago"|…}`
- Create: `design.md` at the repo root, about 60 lines, in the format of `~/.claude/skills/hallmark/references/design-md.md`: the tokens, the lamps, the labels ruling, the components, the brand, the motion character ("severe"), the terminal-island exception and the `.ember` legacy hook note
- Modify: `docs/design/dashboard-ui.md`: replace §1 Tokens, §2 Layout (the rail paragraph) and §10 Light mode (the toggle) with the new direction, pointing to `design.md`; note that the night-watch / morning-ash direction and the house glyph are superseded (2026-11-01, the operator's ruling)
- Modify: `tests/test_light_mode.py` (rulings 1 and 2) and the Task 2 rows of **Presentation pins**: `tests/test_metrics_page.py`, `tests/test_dashboard_actions.py`, `tests/test_needs_attention.py` (lines 198 and 274 only), `tests/test_findings_table.py` (lines 137 and 154 only), `tests/test_pagination.py`, `tests/test_tool_feedback.py` (lines 278, 280, 294), `tests/test_dashboard.py` (line 439 only)
- Modify: the templates holding the action labels and the glyphs: `partials/_incident_acts.html`, `partials/_inv_acts.html`, `partials/_verdict.html`, `partials/_inv_rows.html`, `overview.html` (the `RE-RUN` label, the `●` empty-state line → `<span class="lamp blue" aria-hidden="true"></span> Nothing needs attention.`, and the `💡` tool-feedback lines → `Suggestion: …` / `Suggestion, general: …`; nothing else in overview.html), `incidents.html` (the `LOAD 50 MORE` label, and `🔒` → the word `Locked` with its `title` and the `class="lock"` hook kept), `findings.html` (the `LOAD 50 MORE` label only)
- Test: `tests/test_dashboard_system.py` (new)
- **Pre-flight rulings that bind this task:** (a) the page container must NOT be called `.wrap`: in this app `.wrap`, `.cmd`, `.rfull` and `.prose code, .prose pre` are terminal islands on `var(--term-bg)`, pinned by `test_terminal_surfaces_stay_dark_in_light_mode`; name the console container `.console` (or keep the existing container class). (b) The rail footer element keeps `class="daemon …"` (`tests/test_dashboard.py:188` asserts `"daemon" in html`); its label reads `Connected` / `Daemon quiet` / `No heartbeat yet`. (c) `THEME_ICON` in `app.py` becomes `THEME_WORD = {"auto": "Auto", "light": "Light", "dark": "Dark"}`; `request.state.theme_icon` keeps its attribute name so base.html's fallback keeps working. (d) Secondary block captions (`latest runs`, `tool usage`, `token usage`, `recent investigations`, `recent findings`, `triggered by`, `transcript · …`, `report`, `spend by day`, `by model`, `history · …`) keep their lowercase DOM text and are styled as `.label` mono caps; tests slice the page on that text.

**Interfaces:**
- Consumes: Global Constraints, verbatim; the mockup's CSS.
- Produces, for later tasks: the token names; `.lamp` and its colour classes; `.label`; `.seg`; `.btn`/`.btn.primary`; `.card`/`.panel`/`.grille`; `.tbl`/`tr.flag`; `.runs`; `.gap`/`.bang`; macros `m.lamp(colour)` → `<span class="lamp {colour}" aria-hidden="true"></span>`, `m.seg(items)` where each item is `{"href", "label", "n", "on"}` → the segmented switch with `aria-current="true"` on the engaged one; `m.pill`/`m.sev`/`m.muted` unchanged in signature, the `.dot` now empty, `m.muted` reading `muted · until …` as today; every action label in sentence case (`Re-run`, `Investigate now`, `Mark false positive`, `Unmute`, `Mute`, `Approve`, `Decline`, `Confirm`, `False positive`, `Load 50 more`); the theme toggle `<a class="btn themetoggle" …>` rendering `<span class="lamp ring" aria-hidden="true"></span>Appearance<span class="n">Light</span>` (so `>Light<` matches), aria-labels unchanged.

- [ ] **Step 1: Write the failing tests** in `tests/test_dashboard_system.py`:
  - `test_css_starts_with_the_hallmark_stamp`: the first non-empty line starts with `/* Hallmark ·` and contains `theme: custom`
  - `test_light_ground_is_the_console_grey`: `--bg: #E6E2DA` in the light block, `--bg: #1C1916` in `:root`
  - `test_lamp_tokens_are_mode_invariant`: `--signal`, `--crit`, `--warn`, `--ok` appear in `:root` and not in the light block
  - `test_overflow_clip_on_html_and_body`
  - `test_three_font_weights_only`: the set of `font-weight:` values (and the weight in `font:` shorthands) in `heim.css` is a subset of `{400, 600, 800}`
  - `test_no_emoji_or_status_glyphs_in_templates`: none of `💡 🔒 👍 ☀ ☾ ◐ ● ○ ◌ ◷ ✓ ✗ ✕ ⚠ ✳ ◆ ‖` in any template (`▲` is allowed: a change marker in data)
  - `test_rail_is_grouped_with_lamps_and_counts`: a rendered `/` has `Workspace`, `Infrastructure`, `Insights` as `.label`s, one `.lamp` per nav item, `aria-current="page"` on the current item, `class="n"` counts for Agents, Investigations, Incidents and Hosts, the brand `class="spark"` mark with `class="dot"`, `aria-label="HEIM"`, and `H 01`
  - `test_rail_footer_shows_connection_and_appearance`: `Connected` or `Daemon quiet` or `No heartbeat yet`, and `Appearance`
  - `test_favicon_is_the_compact_mark`: `static/logo.svg` contains `#E8541E` and no `#E88C3A`
  - `test_dot_spans_are_empty_lamps`: a rendered `/incidents` has no `<span class="dot" aria-hidden="true">X</span>` with a non-empty X
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_dashboard_system.py tests/test_light_mode.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** the stylesheet, the shell, the macros, `logo.svg`, `design.md`, the docs, the ruled test changes and the Task 2 pins.
- [ ] **Step 4: Run** the full suite. Expected: PASS, except the known failure. Then the visual check on `/`, `/incidents` and `/investigations/4` in both themes; fix every Floor FAIL (bar the four rulings) in the files this task changed.
- [ ] **Step 5: Commit**

```bash
git add src/heim/dashboard/static/heim.css src/heim/dashboard/static/logo.svg src/heim/dashboard/templates src/heim/dashboard/app.py design.md docs/design/dashboard-ui.md docs/superpowers/plans/2026-11-01-dashboard-redesign.md tests/test_light_mode.py tests/test_dashboard_system.py tests/test_metrics_page.py tests/test_dashboard_actions.py tests/test_needs_attention.py tests/test_findings_table.py tests/test_pagination.py tests/test_tool_feedback.py tests/test_dashboard.py
git commit -m "dashboard: the console system — tokens, lamps, grouped rail, design.md"
```

### Task 3: Overview: cards, Needs attention, Needs you, the Agents panel

**Files:**
- Modify: `src/heim/dashboard/app.py` (the `overview` route and pure helpers), `src/heim/dashboard/format.py` (pure `workflow_for`, `needs_you_label`)
- Modify: `src/heim/dashboard/templates/overview.html`
- Create: `templates/partials/_agents_table.html` (the Agents panel body; Task 4 reuses it), `templates/partials/_needs_you.html`
- Test: `tests/test_overview_console.py` (new)
- Modify: the Task 3 row of **Presentation pins**: `tests/test_needs_attention.py` (lines 197 and 204: `html.index("needs attention")` → `html.index("Needs attention")`). The secondary blocks keep their lowercase `.label` captions (pre-flight ruling 7), so the slices on `latest runs`, `recent investigations` and `tool usage` must keep working: do not rename those captions.
- Modify (local, never commit): `.hallmark/seed_demo.py`, seeding `agent_runs`: about 2 h of poll runs for the three poll agents with one miss and one Uptime Kuma error, daily runs for 3 days, one security run, backup runs with the newest 31 h old

**Interfaces:**
- Consumes: Task 1's `agents.py` and store methods; Task 2's components and macros.
- Produces, in the overview context, **in addition to** every existing key (`kpis`, `token_chart`, `latest_run`, `run_list`, `attention`, `attention_count`, `health`, `tool_usage`, `tool_feedback_general`, `investigations`, `findings`, `empty`, all kept): `condition` (the `overall_condition` dict), `coverage` (`{"reporting": n, "total": 7, "discs": [bool…], "missing": [names]}`), `observations` (`{"since_s", "since_text", "sources": "Prometheus · Uptime Kuma", "ticks": [Tick…]}`), `requires_you` (`{"n", "approvals", "checks"}`), `attention_rows` (each `{"severity", "lamp", "title", "sub", "host", "workflow": {"title", "sub", "href"}, "age", "href"}`), `needs_you` (each `{"kind": "approval"|"check"|"human", "label", "title", "mono", "text", "href", "primary": bool}`), `agents` (each `{"key", "name", "scope", "status": AgentStatus, "last_ok", "strip": [Tick…], "flag": bool, "href": "/agents/<key>"}`), `agents_filter` (`all|running|attention`, from `?agents=`), `agents_counts` (`{"all", "running", "attention"}`), `gaps` (one `{"text", "href", "label"}` per flagged agent), `window` (`live`, until Task 5).
- `format.workflow_for(incident: dict, investigations: list[dict], investigable: set[str]) -> dict` is pure and returns `{"title", "sub", "href"}` per the spec's Workflow list; `investigations` are the rows whose fingerprint matches, newest first.
- `format.needs_you_label(inv: dict) -> str`: `"Approval"` for `pending_approval`; for `needs_human`, `"Physical check"` when the report's remediation section mentions one of `fan, cable, power, reseat, replace, unplug, enclosure, hardware, physically`, else `"Needs a human"`.
- **Attention order:** critical open incidents, then the existing needs-attention investigation rows (incomplete, failed, needs human: with their re-run form), then warning open incidents; oldest first within a group; suppressed excluded. The count is `len(attention_rows)`; the heading reads "n findings".
- **Agents filter:** `all` shows every agent; `running` only `running`; `attention` only `failed`, `degraded`, `stale`, `unknown`. The switch's counts are computed from the same list.
- **Flag and gaps:** an agent is flagged (`tr.flag`) when `stale` or `failed`; its gap line reads `"Monitoring gap: latest {name} result not received."` (stale) or `"Monitoring gap: {name} failed: {error}."` (failed) with the link `"Review {name} runs →"` to `/agents/<key>`.
- The empty state line is `<span class="lamp blue" aria-hidden="true"></span> Nothing needs attention.`; Needs you empty: `Nothing needs you. The agents are handling it.`
- **Soft cap (ruling 15):** the Needs attention table shows at most 6 rows but never hides a critical row; when rows are cut, one `all (n) →` line under the table links to `/incidents`; the header count stays the full count. The `empty_client` fixture in `tests/test_needs_attention.py` seeds a complete investigation instead of an open warning incident (ruling 14), its assertions unchanged.
- The footer line: `HEIM / H 01` and `heim {version}` from the package metadata.

- [ ] **Step 1: Write the failing tests** in `tests/test_overview_console.py`, using the dashboard client fixture pattern from `tests/test_dashboard.py` and seeding `agent_runs`:
  - `test_cards_show_condition_coverage_observations_and_requires_you`
  - `test_no_heartbeats_reads_unknown_not_normal`
  - `test_attention_rows_carry_workflow_and_order`
  - `test_workflow_for_each_incident_kind` (pure)
  - `test_needs_you_lists_approvals_then_checks_and_links_to_detail`
  - `test_needs_you_label_physical_vs_human` (pure)
  - `test_agents_panel_has_seven_rows_filter_and_flag`: `?agents=attention` shows only the overdue backup, with its gap line and `aria-current` on the segment
  - `test_counts_agree_with_rows`: rail counts, card figures and Needs-you count equal the rows rendered
  - `test_existing_overview_blocks_still_render`: one assertion per existing block, by its heading text
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_overview_console.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement.** The first screen at 1440×900 shows the top bar, the four cards, Needs attention and Needs you, and the start of the Agents panel. The existing blocks follow, restyled on the system.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_overview_console.py tests/test_dashboard.py tests/test_needs_attention.py tests/test_token_chart.py tests/test_tool_feedback.py -q`, then the full suite. Then the visual check on `/` and `/?agents=attention`, both themes, at 1440 and 375.
- [ ] **Step 5: Commit**

```bash
git add src/heim/agents.py src/heim/dashboard/app.py src/heim/dashboard/format.py src/heim/dashboard/static/heim.css src/heim/dashboard/templates/overview.html src/heim/dashboard/templates/partials/_agents_table.html src/heim/dashboard/templates/partials/_needs_you.html tests/test_overview_console.py tests/test_needs_attention.py
git commit -m "dashboard: the console overview — cards, needs attention, needs you, agents"
```

### Task 4: The Agents page and the agent detail page

**Files:**
- Modify: `src/heim/dashboard/app.py` (routes `GET /agents` and `GET /agents/{key}`)
- Create: `templates/agents.html`, `templates/agent.html`
- Test: `tests/test_agents_pages.py` (new)

**Interfaces:**
- `GET /agents?agents=all|running|attention`: the full Agents panel (`partials/_agents_table.html`) with its switch, gap lines and key; title "Agents"; the rail marks it current.
- `GET /agents/{key}`: 404 for a key not in `AGENT_KEYS`. Context: the agent's `status`, `scope`, cadence text (`"every 5 min"`, `"twice daily"`, `"weekly"`, `"daily at 03:30"`, `"on demand"`), last success and last error (time and message), the run strip, `runs` as a table (the last 24: time, result lamp + word `OK`/`Error`/`Missed`, duration, what happened from `detail`/`error`), the evidence link per the spec (`alert_poller`, `thresholds`, `uptime` → `/incidents`; `daily` → `/findings`; `investigator` → `/investigations`; `security` → `/security`; `backup` → the last backup file name as text). For `investigator`, `runs` are its investigations (status, host, steps, tokens) with links to each.
- Both pages work without JavaScript; no `hx-*` is needed.

- [ ] **Step 1: Write the failing tests:**
  - `test_agents_page_lists_seven_and_filters`
  - `test_agent_detail_shows_runs_strip_and_evidence_link`
  - `test_agent_detail_404_for_unknown_key`
  - `test_investigator_detail_lists_investigations`
  - `test_rail_marks_agents_current`
- [ ] **Step 2: Run** them. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_agents_pages.py tests/test_overview_console.py tests/test_dashboard.py`, then the full suite. Then the visual check on `/agents` and `/agents/backup`, both themes, at 1440 and 375.
- [ ] **Step 5: Commit**

```bash
git add src/heim/dashboard/app.py src/heim/dashboard/templates/agents.html src/heim/dashboard/templates/agent.html tests/test_agents_pages.py
git commit -m "dashboard: agents page and agent detail"
```

### Task 5: The window switch: Live / 24 h / 7 d

**Files:**
- Modify: `src/heim/agents.py` (pure `bucket_runs`), `src/heim/dashboard/app.py` (`?window=` on `/` and `/agents`; the Observations ruler), `templates/overview.html`, `templates/agents.html`, `templates/partials/_agents_table.html`, and `static/heim.css` for one rule only: `.runs i.none` (a faint dot, `--grille`) for an empty slot
- Test: `tests/test_window.py` (new)

**Interfaces:**
- `bucket_runs(runs: list[dict], cadence_s: int | None, window_s: int, now_iso: str, n: int = 24) -> list[Tick]`: splits `[now - window_s, now]` into `n` equal slots, oldest first; a slot is `fail` if any run in it failed, else `ok` if it has a run, else `miss` when the agent has a cadence and the slot is at least one cadence long (a cadenced agent should have run), else `ok`-less `open` only for the newest slot when it has no run yet; agents with `cadence_s=None` get `ok`/`fail`/nothing (an empty slot renders as a faint dot: `Tick(state="none")`).
- `window` is `live` (default; `run_strip` as in Task 1), `24h` (`bucket_runs` with 86 400 s) or `7d` (604 800 s). Anything else falls back to `live`. The switch in the top bar carries `aria-current="true"` on the engaged segment and keeps the other query params (`qs_with`).
- The Observations card's ruler shows the window's slots for the poll agents merged: a red tick where any poll failed or was missed.
- Nothing else changes with the window; open incidents are what is open now.

- [ ] **Step 1: Write the failing tests:**
  - `test_bucket_runs_marks_fail_miss_and_open` (pure)
  - `test_bucket_runs_without_cadence_never_misses` (pure)
  - `test_window_param_switches_strips_and_marks_segment`
  - `test_bad_window_falls_back_to_live`
- [ ] **Step 2: Run** them. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_window.py tests/test_agents.py tests/test_overview_console.py tests/test_agents_pages.py`, then the full suite. Then the visual check on `/?window=7d`, both themes.
- [ ] **Step 5: Commit**

```bash
git add src/heim/agents.py src/heim/dashboard/app.py src/heim/dashboard/templates tests/test_window.py
git commit -m "dashboard: the window switch — live, 24 h, 7 d run buckets"
```

### Task 6: Investigations list and the investigation page

**Files:**
- Modify: `templates/investigations.html`, `templates/investigation.html`, `templates/partials/_inv_rows.html`, `templates/partials/_inv_acts.html`, `templates/partials/_transcript.html`, `templates/partials/_verdict.html` if used there
- Modify: `src/heim/dashboard/format.py`, adding the pure `report_sections(report_md: str) -> dict`
- Modify: `src/heim/dashboard/app.py`: the `investigation_detail` context gains `sections` and `completed_actions`
- Modify (ruling 17): `templates/partials/_transcript.html` and `templates/overview.html:205` replace the `⛔` glyph with a red lamp plus the word; `tests/test_dashboard.py:307, 411` re-pin `"⛔ blocked"` → `">blocked<"`; `tests/test_dashboard_system.py` adds `⛔` to `RETIRED`
- Test: `tests/test_investigation_sections.py` (new)

**Interfaces:**
- `report_sections(report_md) -> {"interpretation": [(heading, markdown)…], "proposed": […], "other": […], "raw": report_md}`: `## Summary`, `## Root cause`, `## Confidence` → `interpretation`; `## Remediation` and any heading starting with "Remediation", "Recommend" or "Next step" → `proposed`; `## Evidence` and `## Tooling feedback` → `other`; text before the first heading → `other`. Nothing is ever dropped.
- `completed_actions`: a list of `{"what": str, "at": str}` from the investigation row: the approval decision, the outcome (`resolved` / `needs_human`, with its time when known), suppressions on its fingerprint. When empty, the panel says `No actions taken. The agent is read-only; decisions are yours.`
- Page order: header facts (a `.card` row with lamps), Observations (the transcript: terminal islands in `--term-*`, the per-step facts in tabular numerals, the burn line kept), Interpretation, Proposed actions, Completed actions, then the full report (folded `<details>`, always present), the brief, the transcript JSON and the actions, all kept. Section titles are panel `h2`s; the four kinds carry `.label` captions.

- [ ] **Step 1: Write the failing tests:** `test_report_sections_sorts_headings_and_drops_nothing`, `test_incomplete_report_keeps_raw_text`, `test_investigation_page_labels_observations_interpretation_proposed_completed`, `test_no_actions_line_for_untouched_investigation`, `test_waiting_age_and_replay_of_still_shown`
- [ ] **Step 2: Run** them. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_investigation_sections.py tests/test_dashboard.py tests/test_pagination.py tests/test_tracking.py tests/test_model_choice.py tests/test_observability.py`, then the full suite. Then the visual check on `/investigations`, `/investigations/4` (complete), `/investigations/8` (pending) and `/investigations/2` (needs human), both themes, at 1440 and 375.
- [ ] **Step 5: Commit**

```bash
git add src/heim/dashboard/templates/investigations.html src/heim/dashboard/templates/investigation.html src/heim/dashboard/templates/partials/ src/heim/dashboard/format.py src/heim/dashboard/app.py tests/test_investigation_sections.py
git commit -m "dashboard: investigations — observations, interpretation, proposed and completed actions"
```

### Task 7: Incidents and hosts

**Files:**
- Modify: `templates/incidents.html`, `templates/hosts.html`, `templates/partials/_incident_acts.html`, `templates/partials/_host_acts.html`, and `app.py` only if a context key is needed
- Test: `tests/test_incidents_hosts_redesign.py` (new)

**Interfaces:**
- **Ownership** is a word from the description prefix: `Alert` (`[alert] `), `Metric` (`[metric] `), `Uptime` (`[uptime] `), `Daily analysis` (no prefix). The lock is already the word `Locked` with its `class="lock"` hook (done in Task 2); keep it so.
- **Incidents:** a panel with a `.tbl`: lamp + severity, status, ownership, host (mono), metric, fingerprint, seen, missed, actions; the existing filters as a `.seg` when they are discrete, and the existing "Load 50 more".
- **Hosts:** one panel row per host (no card inside a card): role, open incidents by state (lamps), last finding, the existing "Investigate now" form. Report-only addresses (Uptime Kuma, unmapped) appear in a "Watched, not investigated" group when open uptime incidents exist on them.

- [ ] **Step 1: Write the failing tests:** `test_incident_ownership_words`, `test_lock_is_a_word_not_an_emoji_and_keeps_its_hook`, `test_hosts_page_lists_report_only_addresses_separately`, `test_every_incident_action_form_still_posts_to_its_route`
- [ ] **Step 2: Run** them. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_incidents_hosts_redesign.py tests/test_dashboard.py tests/test_dashboard_actions.py`, then the full suite. Then the visual check on `/incidents` and `/hosts`, both themes, at 1440 and 375.
- [ ] **Step 5: Commit**

```bash
git add src/heim/dashboard/templates/incidents.html src/heim/dashboard/templates/hosts.html src/heim/dashboard/templates/partials/ src/heim/dashboard/app.py tests/test_incidents_hosts_redesign.py
git commit -m "dashboard: incidents and hosts on the console system"
```

### Task 8: Findings, security and recommendations, with links to evidence

**Files:**
- Modify: `templates/findings.html`, `templates/security.html`, `templates/recommendations.html`, `templates/partials/_verdict.html`, `templates/partials/_rec_acts.html`, `app.py` (context only), and `templates/metrics.html` only to add an anchor `id="q-<qid>"` per query row if missing
- Test: `tests/test_findings_evidence.py` (new)

**Interfaces:**
- **Every finding row links to its evidence:** the metric, `/metrics#q-<qid>` (qid from `fingerprint.split("|")[1]`, only for daily findings whose qid is in the query catalog); its incident (`/incidents?fingerprint=…` when the page filters by fingerprint, otherwise `/incidents`); its latest investigation when `store.investigation_by_fingerprint` has one.
- Security findings link to their check on `/security` (an anchor per check id).
- Each link is labelled with what it opens: "metric", "incident", "investigation 4".
- Findings run headers are `.card`-style rows with lamps; verdict buttons stay in their forms.

- [ ] **Step 1: Write the failing tests:** `test_daily_finding_links_to_its_metric_incident_and_investigation`, `test_finding_without_catalog_qid_has_no_metric_link`, `test_metrics_rows_carry_q_anchors`, `test_verdict_and_mute_forms_unchanged`
- [ ] **Step 2: Run** them. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_findings_evidence.py tests/test_findings_table.py tests/test_security_dashboard.py tests/test_recommendations.py tests/test_dashboard_actions.py`, then the full suite. Then the visual check on `/findings`, `/security` and `/recommendations`, both themes, at 1440 and 375.
- [ ] **Step 5: Commit**

```bash
git add src/heim/dashboard/templates/ src/heim/dashboard/app.py tests/test_findings_evidence.py
git commit -m "dashboard: findings, security, recommendations — each finding links to its evidence"
```

### Task 9: Metrics and costs: functional charts

**Files:**
- Modify: `templates/metrics.html`, `templates/costs.html`, the token chart block in `templates/overview.html`, the chart helpers in `src/heim/dashboard/format.py` (`bar_chart` and any sparkline helper), `app.py` (context only)
- Read first: `~/.claude/skills/hallmark/references/data-viz.md`
- Test: `tests/test_functional_charts.py` (new)

**Interfaces:**
- **Every chart carries** a one-line question in its caption, the unit, the window and the observations behind it:

  | Chart | Question | Unit | Window |
  |---|---|---|---|
  | token chart | "Is agent spend steady?" | tokens per day | 14 days |
  | cost chart | "What did the agents cost?" | the configured currency per day | |
  | each metrics row | the label's own question, e.g. "Is the disk filling?" for `fs_used` | the catalog unit | 3 days |

- **Thresholds:** the catalog's `warn` and `crit` values are drawn as labelled hairlines when the row's direction is `high` or `low`.
- **Gaps:** a missing observation (`null`) is drawn as a gap and marked "no data", never as zero. A real zero stays zero.
- The format helpers stay pure and keep their existing signatures; new optional keyword arguments may be added. Bars are `--ink`; threshold lines `--warn` and `--crit`; gaps `--grille`.

- [ ] **Step 1: Write the failing tests:** `test_token_chart_has_question_unit_and_window`, `test_metrics_row_draws_warn_and_crit_lines`, `test_missing_observation_is_a_gap_not_zero`, `test_cost_chart_caption`
- [ ] **Step 2: Run** them. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_functional_charts.py tests/test_metrics_page.py tests/test_costs_page.py tests/test_token_chart.py`, then the full suite. Then the visual check on `/metrics`, `/costs` and `/`, both themes, at 1440 and 375.
- [ ] **Step 5: Commit**

```bash
git add src/heim/dashboard/templates/ src/heim/dashboard/format.py src/heim/dashboard/app.py tests/test_functional_charts.py
git commit -m "dashboard: functional charts — question, unit, window, thresholds, gaps"
```

### Task 10: Error page, phones, the kept check, docs

**Files:**
- Modify: `templates/error.html`, any template or `heim.css` rule the sweep names, `README.md` (the dashboard paragraph and screenshots note), `AGENTS.md` (§1 Dashboard row: the console, the Agents page, heartbeats, the window; §5.7 or a new line: `agent_runs`; §2 the `design.md` pointer)
- Test: `tests/test_dashboard_system.py` (extend)

- [ ] **Step 1: Write the failing test:** `test_error_page_uses_the_system`, which renders the 404 page and checks that it has the shell, a plain-language line and a link home.
- [ ] **Step 2: Run** it. Expected: FAIL.
- [ ] **Step 3: Implement the error page, then run the whole-app sweep.**
  - `node ~/.claude/skills/hallmark/scripts/sloplint.mjs src/heim/dashboard --genre modern-minimal --scope app --render --kept` with `--url` for every route in the spec's list (ids from `.hallmark/demo/ids.json`), both themes.
  - Fix every FAIL, including any `FAIL kept`, bar the four rulings. Record the four rulings as `waive` lines in the `heim.css` stamp, each with its reason ("operator's console concept, 2026-11-01").
  - Fix or waive every other REFLEX in the stamp, with a reason each.
  - Confirm there is no sideways scrolling at 375 and 320 on every route.
  - Update the README and AGENTS.md.
- [ ] **Step 4: Run** the full suite. Expected: PASS, except the known failure. Report the path `.hallmark/compare.html` and the final sloplint counts.
- [ ] **Step 5: Commit**

```bash
git add src/heim/dashboard/ README.md AGENTS.md tests/test_dashboard_system.py
git commit -m "dashboard: error page, phone layouts, kept check; document the console"
```
