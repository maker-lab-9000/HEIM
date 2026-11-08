# Activity, Jobs and Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the dashboard's Agents section into:
- **Activity:** a map and a causal timeline;
- **Jobs:** with timed pauses;
- **Agents:** analyst, investigator, auditor, each with its prompt;
- **Tools:** definitions and feedback.

Causality is recorded at creation, never inferred.

**Architecture:**
- **Heartbeats open when a job starts.** The daemon opens the `agent_runs`
  row at the start of a job, not the end, and puts its id in a
  `contextvars` run context. Pipelines read that context to stamp the rows
  they create: investigations, the `runs` row, and the new `incident_events`
  rows. Dispatched investigation tasks inherit the context, because
  `asyncio.create_task` copies it.
- **Pauses are store rows the daemon obeys.** The poll cycle announces pause
  starts and ends, and pings the dead-man's switch regardless.
- **Pure assembly modules:** `heim/activity.py` (timeline + map) and
  `heim/jobs.py` (pause state, job table). The dashboard only renders them.

**Tech Stack:** Python 3.12, SQLite (WAL), FastAPI + Jinja + htmx, pytest
(`asyncio_mode = "auto"`).

**Spec:** `docs/superpowers/specs/2026-11-04-activity-jobs-tools-design.md`

## Global Constraints

- **Golden modules stay byte-identical:** `reconcile.py`, `poller_logic.py`
  and `reports/daily_dashboard.py`. Causal ids are added in the pipelines,
  the daemon and the store.
- **Dashboard writes:** the only new ones are `pause_job` and `resume_job`,
  through `_ACTION_HELPERS`. Heartbeats are still written only by daemon job
  wrappers.
- **Pauses:**
  - durations are exactly `1h`, `4h` and `24h`; any other value is a 400;
  - a pause always has an `until`;
  - a paused poll half skips its work, but the poll cycle completes and
    `deadman.ping` still runs.
- **Telegram lines,** sent by the daemon from the poll cycle, once each:
  - `⏸ HEIM: <Job name> paused until <HH:MM> (<set_by>)`
  - `▶ HEIM: <Job name> resumed`
- **Words:**
  - "Paused" = a dashboard pause, shown as `Paused until HH:MM`;
  - "Off" = switched off in config.
- **New routes:** `/activity`, `/jobs`, `/jobs/<key>`, `/agents` (3 rows),
  `/agents/analyst|investigator|auditor`, `/tools`, `/tools/<name>`.
- **Redirects, all 302:**
  - `/agents/daily` → `/agents/analyst`;
  - `/agents/security` → `/agents/auditor`;
  - `/agents/{alert_poller,thresholds,uptime,backup}` → `/jobs/<key>`.
- **Keys:** job keys = today's `agent_runs.agent` keys (`daily`,
  `alert_poller`, `thresholds`, `uptime`, `security`, `backup`), with no
  data rename. The `model_overrides` keys are unchanged.
- **design.md:**
  - lamps and words, no emoji in the UI;
  - the stylesheet cap test stays green; raise the cap only with a design.md
    note;
  - the map is added to design.md as a component;
  - on phones the map restacks into three lists.
- **`pytest -q` stays green,** apart from the known local-settings failure.

## Review Focus

1. **A pause that expires mid-cycle.** `until` falls between two polls. The
   next cycle runs the half and sends exactly one "resumed" line, with no
   repeat on later cycles. Tested in Task 3.
2. **"Resume now" on an already-expired pause, or two pauses back to back**
   (pause → resume → pause). Each gets its own announce pair; nothing is
   lost or doubled. Tested in Task 3.
3. **An investigation dispatched by the daily run outlives the job.** It
   finishes after the daily heartbeat is closed, and still nests under that
   run (the context was copied into the task). Tested in Task 2.
4. **Rows from before this change** (no parent ids, empty `incident_events`).
   The timeline shows them top-level and labelled, and never crashes or
   guesses. Tested in Task 6.
5. **A filter for a box with no runs in the window,** e.g. `/activity?part=backup`
   in Live. It shows an empty state, not a 500 or the unfiltered list.
   Tested in Task 6.

---

### Task 1: Store — run context columns, incident events, job pauses

**Files:**
- Modify: `src/heim/incidents/store.py`
- Create: `src/heim/jobs.py` (pure)
- Test: `tests/test_jobs_pause.py` (new; not to be confused with the existing `tests/test_jobs.py`, which covers the queue)

**Interfaces:**
- **Produces, store:**
  - `start_agent_run(agent: str, started_at: str) -> int`, which inserts
    with `finished_at=''`;
  - `finish_agent_run(run_id: int, finished_at: str, ok: bool, error: str = "", detail: dict | None = None) -> None`;
  - `record_agent_run` stays, for callers that don't need an id.
- **Produces, new columns:**
  - `investigations.parent_run_id INTEGER NOT NULL DEFAULT 0`;
  - `runs.agent_run_id INTEGER NOT NULL DEFAULT 0`;
  - `runs.input_text TEXT NOT NULL DEFAULT ''`.
- **Produces, table `incident_events`:**
  `(id, run_id INTEGER, fingerprint TEXT, event TEXT, severity TEXT, host TEXT, at TEXT)`,
  where `event` ∈ {`new`, `escalated`, `resolved`}. Helpers:
  `add_incident_events(run_id: int, at: str, events: list[dict]) -> int` and
  `incident_events_for(run_ids: list[int]) -> dict[int, list[dict]]`.
- **Produces, table `job_pauses`:**
  `(job TEXT PRIMARY KEY, until TEXT, set_at TEXT, set_by TEXT, announced_start INTEGER DEFAULT 0, announced_end INTEGER DEFAULT 0)`.
  Helpers:
  - `pause_job(job: str, until: str, set_by: str = "dashboard", set_at: str = "") -> None`
    (upsert; it resets both announce flags);
  - `resume_job(job: str, now: str) -> bool` (sets `until = now`, keeps the
    row so the daemon can announce the end; False if there is no row);
  - `job_pauses() -> dict[str, dict]`;
  - `mark_pause_announced(job: str, which: Literal["start","end"]) -> None`.
- **Produces, `prune`:** deletes `incident_events` older than
  `AGENT_RUNS_RETENTION_DAYS`, and `job_pauses` rows whose end was announced.
- **Produces, `heim/jobs.py`:**
  - `JOB_KEYS = ("daily", "alert_poller", "thresholds", "uptime", "security", "backup")`;
  - `PAUSE_CHOICES = {"1h": 3600, "4h": 14400, "24h": 86400}`;
  - `pause_active(row: dict | None, now_iso: str) -> bool`;
  - `pause_until(now_iso: str, choice: str) -> str` (raises ValueError on a
    bad choice);
  - `announcements(pauses: dict[str, dict], now_iso: str) -> list[tuple[str, Literal["start","end"]]]`,
    which lists what must be announced now: unannounced starts of active
    pauses, and unannounced ends of expired ones. A pause that expired
    before its start was announced yields both, start first.
  - `incident_changes(loki_events: list[dict]) -> list[dict]`, which keeps
    `event == "incident"` with `labels.status` in {new, escalated,
    resolved} and maps it to `{fingerprint, event, severity, host}`.

- [ ] **Step 1: Write the failing tests:**
  - `test_start_and_finish_agent_run`: the row has empty `finished_at`
    until finished, then ok/error/detail.
  - `test_new_columns_and_tables_migrate_on_old_db`: drop the three
    columns and both tables, reopen, and check that they exist.
  - `test_incident_events_round_trip_and_prune`.
  - `test_pause_resume_rows`: after `pause_job`, a row with both flags 0;
    after `resume_job(now)`, `until == now`; a re-pause resets the flags.
  - `test_pause_active_and_until`: `pause_until("2026-11-04T10:00:00+01:00","4h") == "2026-11-04T14:00:00+01:00"`;
    `"2h"` raises.
  - `test_announcements`: cover active-unannounced → start;
    expired-and-started → end; expired-never-started → [start, end];
    everything announced → []. (Review Focus 1–2.)
  - `test_incident_changes_filters_statuses`: open/ongoing events are
    dropped, and non-incident events are ignored.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_jobs_pause.py -q`.
  Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the new tests, then the full suite. Expected: green.
- [ ] **Step 5: Commit** `feat(store): run links, incident events and job pauses`.

### Task 2: Run context — open heartbeats at start, stamp what runs create

**Files:**
- Create: `src/heim/runctx.py`
- Modify: `src/heim/daemon.py` (`_daily_job`, `_poll_job`, `_security_audit_job`, `_backup_job`, `_record_poll_agents`)
- Modify: `src/heim/pipelines/investigate.py` (`run_investigation`: create row with `parent_run_id`)
- Modify: `src/heim/pipelines/daily.py` (the `insert_run`: `agent_run_id`, `input_text=user`; incident events)
- Modify: `src/heim/pipelines/poller.py` (both halves), `src/heim/pipelines/uptime.py` (incident events)
- Test: `tests/test_activity_links.py` (new)

**Interfaces:**
- **Produces, `heim/runctx.py`:**
  - `run_ids: ContextVar[dict[str, int]]`, default `{}`;
  - `set_runs(mapping: dict[str, int]) -> Token`;
  - `current_run(job: str) -> int`, which returns 0 when absent;
  - `TRIGGER_JOB = {"daily": "daily", "poller": "alert_poller", "threshold": "thresholds", "uptime": "uptime"}`.
- **Behaviour:**
  - **Daily, security and backup wrappers:** `start_agent_run` at the
    start, `set_runs({key: id})`, then `finish_agent_run` with today's
    ok/error/detail. On a failure to open, fall back to `record_agent_run`
    at the end (a side channel never breaks a job).
  - **`_poll_job`:** opens one row per *enabled* half before `run_poll`, and
    `_record_poll_agents` finishes them (same ok/error/detail rules as
    today).
  - **`run_investigation`:** a newly created row stores
    `parent_run_id=current_run(TRIGGER_JOB.get(trigger, ""))`. Re-arm keeps
    its stored value.
  - **The daily pipeline:** `insert_run(..., agent_run_id=current_run("daily"), input_text=user)`
    and
    `add_incident_events(current_run("daily"), run_at, incident_changes(<the filtered incident events it emits>))`.
  - **Poller alert half, threshold half and uptime:** the same, with their
    own job key, from `dec.loki_events` after suppression filtering.

- [ ] **Step 1: Write the failing tests.** Use the daemon wrappers with
  faked pipelines, and the pipelines with the existing fakes from
  `tests/test_tracking.py` / `tests/test_uptime_pipeline.py`.
  - `test_daily_job_opens_heartbeat_first`: inside the faked `run_daily`,
    `current_run("daily")` is non-zero and that `agent_runs` row has an
    empty `finished_at`; after the job, it is finished and ok.
  - `test_dispatched_investigation_records_parent` (Review Focus 3):
    dispatch through `dispatch_all(..., concurrent=True, trigger="daily")`
    inside a `set_runs({"daily": 7})` context, and await the task after the
    context is reset. The row's `parent_run_id == 7`.
  - `test_manual_investigation_has_no_parent`.
  - `test_daily_run_row_links_and_stores_input`: `runs.agent_run_id` is set,
    and `input_text` contains the payload's first query id.
  - `test_poll_halves_write_incident_events`: an alert that opens a new
    incident gives one `incident_events` row with event `new` under the
    alert_poller run id.
  - `test_poll_job_heartbeats_unchanged`: the existing heartbeat assertions
    in `tests/test_agents.py` still pass (run them).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the new tests, then `tests/test_agents.py`,
  `tests/test_tracking.py`, `tests/test_uptime_pipeline.py`,
  `tests/test_analyst_chain.py`, then the full suite. Expected: green.
- [ ] **Step 5: Commit** `feat: record which run started what`.

### Task 3: Pausing in the daemon, and Paused vs Off in statuses

**Files:**
- Modify: `src/heim/daemon.py`, `src/heim/pipelines/poller.py` (`run_poll(..., skip: frozenset[str] = frozenset())`)
- Modify: `src/heim/agents.py` (`_STATES` gains `"off": "Off"`; config-off specs use `off`; a latest run with `detail.paused` → `paused`)
- Test: `tests/test_jobs_pause.py` (append)

**Interfaces:**
- Consumes: Task 1 store helpers and `heim.jobs`.
- **Produces:**
  - `async _announce_pauses(rt) -> None`, called at the start of every
    `_poll_job` (before the work, so a pause is announced within one
    cycle). It sends each announcement through `rt.notify` and marks it.
    It never raises.
  - `_paused(rt, job) -> bool`.
  - When paused, the daily, security and backup wrappers record
    `finish_agent_run(..., ok=True, detail={"paused": True, "until": …})`
    and return without running.
  - The poll job passes `skip={paused halves}` to `run_poll` and records
    the paused halves the same way. The dead-man ping still follows a
    completed cycle.

- [ ] **Step 1: Write the failing tests:**
  - `test_paused_half_skips_work_but_ping_still_runs`: pause
    `alert_poller`; patch `deadman.ping` and `_run_alerts`. One `_poll_job`
    gives `_run_alerts` not called, the ping called once, and a heartbeat
    with `detail.paused`.
  - `test_paused_daily_does_not_run`.
  - `test_announce_start_then_end_once` (Review Focus 1): pause 1h →
    cycle → one ⏸ line; advance the clock past `until` → cycle → one ▶
    line; another cycle → no line. Use `Runtime.now` monkeypatching, as
    other tests do.
  - `test_resume_now_and_repause` (Review Focus 2).
  - `test_off_vs_paused_status`: `threshold_detection=False` gives state
    `off`, word "Off"; a latest heartbeat with `detail.paused` gives
    `paused`. Update existing assertions in `tests/test_agents.py` that
    expected "paused" for config-off, and ledger the change.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the new tests, then the full suite. Expected: green.
- [ ] **Step 5: Commit** `feat(daemon): timed job pauses; Paused vs Off`.

### Task 4: Jobs pages, the pause actions, Agents narrowed, rail and redirects

**Files:**
- Modify: `src/heim/dashboard/app.py` (routes, `_ACTION_HELPERS += pause_job, resume_job`, nav groups, `_PANEL_BY_PAGE` page keys → `analyst` / `investigator`)
- Create: `templates/jobs.html`, `templates/job.html` (from today's `agent.html` job parts), `templates/partials/_pause_ctl.html`
- Modify: `templates/agents.html`, `templates/agent.html` (three agents; Prompt section)
- Test: `tests/test_jobs_pages.py` (new); update `tests/test_agents_pages.py` and `tests/test_dashboard_models.py` URLs

**Interfaces:**
- Consumes: `heim.jobs` (Task 1), statuses (Task 3).
- **Produces:**
  - **`POST /actions/pause`:** fields `job ∈ JOB_KEYS`, `for ∈ PAUSE_CHOICES`
    (else 400); writes `pause_job(job, pause_until(now, for))`. A job that
    is Off returns 400 with "switched off in config". It responds like
    other actions: 303, or the `_pause_ctl` partial for htmx.
  - **`POST /actions/resume`:** field `job`; `resume_job(job, now)`.
  - **`AGENT_PAGES = {"analyst": ("daily", "Daily analyst"), "investigator": ("investigator", "Investigator"), "auditor": ("security", "Security auditor")}`**,
    mapping each page key to its heartbeat key and name.
  - **The Prompt section on `/agents/<page>`:**
    - the template file text from `config/prompts/` (`analyst.md`,
      `investigator.md.j2`, `security_auditor.md.j2`);
    - for the investigator, a host select rendering
      `build_system_prompt(...)` for that host (read-only, via the existing
      function with a dashboard-built Runtime-less call; if it needs a
      Runtime, extract the pure part);
    - for the analyst, the latest daily run's `input_text` in a
      `<details>`.
  - **Rail Workspace:** Overview, Activity, Jobs, Agents, Tools,
    Investigations, Incidents. Jobs shows a count of active pauses.

- [ ] **Step 1: Write the failing tests:**
  - `test_jobs_list_has_six_jobs_with_controls`.
  - `test_pause_action_writes_row_and_shows_until`: post
    `job=alert_poller&for=4h` → 303; the store row exists; `/jobs`
    shows "Paused until".
  - `test_pause_rejects_bad_duration_and_unknown_job`: both 400.
  - `test_pause_off_job_rejected`.
  - `test_resume_action`.
  - `test_agents_page_lists_three`: the analyst, investigator and auditor
    are present, with no "Alert poller".
  - `test_old_agent_urls_redirect_302`: all six mappings.
  - `test_analyst_page_has_models_panel_and_prompt`: `id="h-models"`, the
    first line of `config/prompts/analyst.md`, and the latest
    `input_text`.
  - `test_investigator_prompt_renders_for_host`:
    `/agents/investigator?host=ubuntu-server` contains that host's facts.
  - `test_rail_order`.
  - `test_pause_helpers_allow_listed`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** Move today's job-only blocks (run strip,
  monitoring gaps, backup file) to `job.html`; keep shared macros.
- [ ] **Step 4: Run** the new tests, the dashboard tests, then the full
  suite. Expected: green.
- [ ] **Step 5: Commit** `feat(dashboard): Jobs with timed pauses; Agents narrowed to three`.

### Task 5: Tools pages, with the tooling feedback moved there

**Files:**
- Modify: `src/heim/dashboard/app.py`; create `templates/tools.html` and `templates/tool.html`
- Modify: `templates/agents.html` and `templates/agent.html` (feedback blocks removed; link to Tools); `templates/overview.html` (tool-usage card links to `/tools`)
- Test: `tests/test_tools_pages.py` (new); update the existing feedback-location assertions in `tests/test_tool_feedback.py` / `tests/test_agent_tool_calls.py`

**Interfaces:**
- **`/tools`:** one row per `cfg.tools` entry: name, description, "used by"
  (the agents whose YAML lists it), calls and blocked calls in the window,
  and the latest feedback line. Plus the unmatched ("general") feedback.
- **`/tools/<name>`:**
  - the definition, from `Tool.openai_schema()["function"]` on a bare
    instance, or directly from `ToolCfg`;
  - a guard paragraph from a fixed `TOOL_GUARDS: dict[str, str]` in
    `app.py`, one sentence per tool;
  - recent calls across agents;
  - all feedback for the tool.

  An unknown name gives a 404.

- [ ] **Step 1: Write the failing tests:**
  - `test_tools_list_names_every_configured_tool`.
  - `test_tool_detail_shows_schema_used_by_and_feedback`.
  - `test_unknown_tool_404`.
  - `test_general_feedback_on_tools_list`.
  - `test_agents_pages_no_longer_carry_feedback`.
  - `test_every_tool_has_a_guard_sentence`: `set(TOOL_GUARDS) == set(cfg.tools)`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the new tests, the dashboard tests, then the full
  suite. Expected: green.
- [ ] **Step 5: Commit** `feat(dashboard): Tools pages with tooling feedback`.

### Task 6: Activity — map and causal timeline

**Files:**
- Create: `src/heim/activity.py` (pure), `templates/activity.html`, `templates/partials/_activity_map.html`, `templates/partials/_timeline.html`
- Modify: `src/heim/dashboard/app.py` (route), `src/heim/dashboard/static/heim.css` (map + indentation), `design.md` (Activity map component)
- Test: `tests/test_activity.py` (new)

**Interfaces:**
- **`MAP_EDGES: list[tuple[str, str]]`:** fixed job → agent edges
  (`daily→analyst`, `daily→investigator`, `alert_poller→investigator`,
  `thresholds→investigator`, `uptime→investigator`, `security→auditor`),
  plus agent → tool edges from `cfg.agents[*].tools`, computed by
  `map_model(cfg, statuses: dict[str, dict]) -> dict` →
  `{"jobs": [...], "agents": [...], "tools": [...], "edges": [...]}`.
- **`timeline(agent_runs: list[dict], runs_by_agent_run: dict[int, dict], invs: list[dict], events_by_run: dict[int, list[dict]], steps_count: dict[int, int], part: str = "", kind: str = "all") -> list[dict]`.**
  Each node is `{kind: job|agent|tool|event, key, at, lamp, word, text, href, children: [...]}`:
  - **job node:** one per heartbeat;
  - **analyst node:** under a daily heartbeat whose `runs` row links to it
    (model, fallback, finding count);
  - **incident event nodes:** under their run;
  - **investigation nodes:** under the job (or the analyst node, for a
    daily run) whose id is in `parent_run_id`; each carries "N tool calls"
    and the auditor's run under `security`;
  - **unlinked investigations** (manual, dashboard, retry, or legacy rows
    with `parent_run_id == 0`) are top-level, labelled by trigger, and
    legacy ones read "started before run links were recorded".

  Ordering is newest first. `part` filters to nodes whose key or any
  descendant's key is `part`. `kind` ∈ {all, jobs, agents, triggered}.
- **Route `/activity`:** takes `?window=`, `?part=`, `?kind=`; the map's
  boxes link to `?part=<key>`, and a second click (the active box) links
  to the unfiltered page.

- [ ] **Step 1: Write the failing tests** (pure, `heim.activity`, on hand-built rows):
  - `test_daily_tree`: job → analyst → incident event and investigation →
    "9 tool calls".
  - `test_poller_tree_with_escalation`.
  - `test_unlinked_and_legacy_rows_top_level_labelled` (Review Focus 4).
  - `test_filter_by_part_keeps_ancestors`: `part="ssh_diagnostic"` keeps
    the investigation and its ancestors.
  - `test_filter_with_no_match_is_empty` (Review Focus 5).
  - `test_kind_triggered_drops_quiet_runs`.
  - `test_paused_heartbeat_reads_paused`.
  - `test_map_edges_follow_agent_yaml`.

  Route tests:
  - `test_activity_page_renders_map_and_timeline`.
  - `test_activity_part_filter_link_toggles`.
  - `test_activity_empty_part_shows_empty_state`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** The map is a CSS grid of three columns (it
  restacks under the existing phone breakpoint), boxes are links, and the
  edges are implied by columns plus each box's "→ feeds" line. No SVG is
  needed unless design.md asks for one. Add the component to design.md.
- [ ] **Step 4: Run** the new tests, the stylesheet cap test, then the full
  suite. Expected: green.
- [ ] **Step 5: Commit** `feat(dashboard): Activity — map and causal timeline`.

### Task 7: Overview, docs

**Files:** `templates/overview.html` (the Agents panel becomes three small
groups: Jobs, Agents and Tools, each linking to its page, plus a "See
Activity" link), `AGENTS.md` (§1 Dashboard row, the §5.3 note, test count),
`docs/DASHBOARD.md` (pages + the pause action), `docs/OPERATIONS.md` (pausing
for maintenance), and `README.md` if it lists pages.

- [ ] **Step 1: Write a failing test,**
  `test_overview_groups_jobs_agents_tools`, in
  `tests/test_overview_console.py`.
- [ ] **Step 2: Run, implement, run.** Update the docs.
- [ ] **Step 3: Run** the full suite. Expected: green.
- [ ] **Step 4: Commit** `docs+overview: Activity, Jobs and Tools`.
