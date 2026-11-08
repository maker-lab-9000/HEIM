# Activity, Jobs and Tools: splitting the Agents section — design

Date: 2026-11-04 · Status: draft for approval · Builds on the dashboard console
(`2026-11-01-dashboard-redesign-design.md`, `design.md`) and the two model-choice
branches (`feat/analyst-provider-chain`, `feat/investigator-openrouter`).

## Why

The dashboard's **Agents** section mixes three different kinds of thing in one
list of seven "agents":

- scheduled, model-free **jobs**: the alert poller, thresholds, uptime and
  backup;
- the three things that call a model, the real **agents**: the daily analyst,
  the investigator and the security auditor;
- the **tools** the agents call, with tooling feedback scattered over the
  overview, `/agents` and `/agents/<key>`.

The operator opens it to answer one question: **which agent ran when, and what
it triggered.** Today the answer is spread over Agents, Investigations,
Incidents and Findings, joined only by timestamps in their head.

They also want to:

- **pause a job during maintenance**, with the dead-man ping kept running;
- **see the prompt or context** used by each agent and tool.

## Goals

1. **Activity** (new page): one place that answers "what ran, when, and what
   did it start". It has two parts:
   - a **map** on top, showing how the parts are wired: jobs → agents →
     tools, each with a status lamp and its last run;
   - a **timeline** below: every run newest first, with what it started
     **nested under it**. Clicking a box on the map filters the timeline to
     that part. (Operator's choice: "both".)
2. **Jobs** (new page): the scheduled parts, each with its schedule, recent
   runs and a **Pause / Resume** control.
3. **Agents**: narrowed to the analyst, the investigator and the security
   auditor. Each page shows its Models panel (both now exist), its runs, and
   its **prompt / context**.
4. **Tools** (new page): every tool's definition as the model sees it, its
   guard, which agents use it, recent calls, and the **tooling feedback**
   (moved here).
5. **Rail, under Workspace:** Overview, Activity, Jobs, Agents, Tools,
   Investigations, Incidents.

## Non-goals

- No change to what any job, agent or tool *does*: detection, prompts,
  guards and schedules are untouched. This is a view of the system, plus one
  new control (pause).
- No editing of prompts, schedules or tool definitions from the dashboard.
  They stay config in git.
- Grafana stays the place for time-series. Activity is a run log, not a
  chart.

## Anti-goals

- **A pause that silences the watchdog.** While a job is paused, the poll loop
  keeps running and the dead-man's switch keeps pinging. Only the paused
  job's work is skipped. (Operator's ruling.)
- **A forgotten pause.** Every pause ends by itself at a time the operator
  chose (operator's ruling). "Paused" is visible on the Overview, the
  Activity map, the Jobs page and the rail, and is never mistaken for
  "healthy, nothing happened".
- **Guessed causality.** The timeline nests a child under a parent only when
  the link was **recorded** when the child was created, never by matching
  timestamps. Older rows with no recorded link show un-nested, under an
  honest label. A wrong nesting is worse than none.
- **Showing secrets.** Prompts and context are rendered from config that is
  already `${VAR}`-interpolated with deployment identity (IPs, users). The
  dashboard is LAN-only behind basic auth, so showing them is in scope. API
  keys and tokens are never part of a prompt and must not appear.

## What the operator sees

### Rail

Workspace: **Overview · Activity · Jobs · Agents · Tools · Investigations ·
Incidents**. The other groups are unchanged. Jobs carries a count of paused
jobs, and only when one is paused.

### Activity (`/activity`)

- **Map.** Three columns:
  - **Jobs:** daily run, alert poller, thresholds, uptime, security audit,
    backup;
  - **Agents:** analyst, investigator, security auditor;
  - **Tools:** the tools in `config/tools/`.

  Each box has a lamp and word (design.md), the last run, and one short fact
  ("deepseek · fallback", "1 waiting", "14 calls today"). The edges come from
  config, not from data:
  - the daily run → the analyst, and → the investigator (it dispatches);
  - the alert poller, thresholds and uptime → the investigator;
  - the security audit → the auditor;
  - each agent → the tools its YAML lists.

  Clicking a box filters the timeline to it. Clicking again clears the
  filter.
- **Timeline.** Newest first, inside the existing Live / 24 h / 7 d window
  switch. Each row shows the time, the kind (job · agent · tool), a
  lamp + word, and a one-line summary. Children are indented under their
  parent:
  - **daily run (job):** → analyst (model, fallback or not) → "N findings ·
    opened/escalated incidents" → each investigation it dispatched → that
    investigation's tool calls (collapsed to "9 tool calls", expandable);
  - **poller / thresholds / uptime:** → incidents they opened → the
    investigations they dispatched;
  - **security audit:** → the auditor's run → its tool calls;
  - **backup:** the file written and the rows pruned;
  - **manual, dashboard and retry investigations:** top-level rows, labelled
    with who started them.

  Filters: all · jobs · agents · only runs that triggered something. Paused
  slots show as "paused" rows, not gaps.

### Jobs (`/jobs`, `/jobs/<key>`)

- **List:** each job with its lamp + word, schedule, last run, next run, and
  the Pause/Resume control.
- **Detail:** today's job page content (run strip, run table,
  monitoring-gap lines) plus the control.
- **Pause:** pick a duration: **1 h, 4 h or 24 h** *(my call, see below)*.
  Then "Paused until 14:30 · Resume now".
- **When the time is up**, the job resumes by itself.
- **Telegram** gets one line when a pause starts and one when it ends, early
  or on time *(my call)*, e.g. `⏸ HEIM: Alert poller paused until 14:30
  (dashboard)` and `▶ HEIM: Alert poller resumed`.
- **"Paused" vs "Off":** "Paused" means paused from the dashboard. A job
  switched off in config (thresholds with `threshold_detection: false`,
  uptime with no URL, the audit with `security_audit: ""`) shows **Off**, and
  its control says why it can't be resumed here. Today both are called
  "Paused"; the words split *(my call)*.

### Agents (`/agents`, `/agents/<key>`)

- **List:** only the three agents, with model, last run and lamp.
- **Detail:**
  - the Models panel (unchanged);
  - its runs;
  - a **Prompt** section with the system prompt template from
    `config/prompts/`, as written;
  - a **"rendered for"** view: the analyst's prompt as sent; the
    investigator's rendered for a chosen host; the auditor's as sent.
- **Per-run context:** from a run (an investigation page, or a daily run row
  in Activity), "what it was given":
  - **investigator and auditor:** the stored brief (`brief_md`), plus the
    transcript when `store_transcripts` is on (both exist today);
  - **daily analyst:** its user message (the aggregated payload and the
    suppression hint) is **not stored today**, and from now on is stored
    with each daily run, under the same retention as runs.

### Tools (`/tools`, `/tools/<name>`)

- **List:** each tool with its description, which agents use it, calls and
  blocked calls in the window, and the latest feedback line.
- **Detail:**
  - the definition exactly as the model sees it (description and input
    schema, the same object both loops send);
  - its guard or scope in one paragraph (e.g. "read-only SSH, commands
    validated by `guards/ssh_guard`; sudoers-scoped");
  - recent calls (agent, investigation, args, blocked, duration);
  - **all tooling feedback** for this tool. Unmatched feedback names (the
    current "Suggestion, general") go on the `/tools` list page.

### Overview

The Agents panel there becomes three small groups (jobs, agents, tools), or
links into Activity. Its tool-usage card links to `/tools`. *(Exact layout is
left to the builder, within design.md.)*

## How it works (decided)

- **Pause is a store row the daemon obeys.** It follows the established
  pattern: the dashboard writes, through an `_ACTION_HELPERS` helper, a row
  meaning "job X paused until T, set by …". The daemon reads it each time
  that job is due. While `now < until` it skips the work and records the run
  as paused (so the strip shows "paused", not a gap or "overdue"). For the
  poll loop it skips only the paused half, and the dead-man ping still runs
  after every cycle. A row whose time has passed is simply not in effect:
  resuming needs no timer. *(Builder check; my call.)* The dashboard has no
  Telegram access, so the daemon sends both lines. It checks the pause rows
  on **every poll cycle** (5 min), whichever job they concern. It sends
  "paused" for a row it has not announced yet, and "resumed" once a row's
  time has passed or it was cleared by "Resume now". Each line arrives within
  one poll interval. A small "announced" flag on the row stops repeats.
- **Causal links are recorded at creation.** Rows created by a run record
  the id of that run, and the timeline nests by that id only:
  - investigations dispatched by the daily run, the poller, thresholds or
    uptime;
  - findings from a daily run.
- **Incident events are recorded per run** *(builder check; decided from the
  goal "what it triggered")*. An incident row is reopened and escalated many
  times, so one parent column cannot say which run did what. A new
  `incident_events(run_id, fingerprint, event, severity, at)` table records
  every **open, reopen, escalate and resolve**. It is written by the
  pipelines (daily reconcile and the three poll halves) from the decisions
  the golden modules already return; the golden modules stay untouched. The
  timeline shows these events under the run that caused them. The table is
  pruned like `agent_runs`.

  The builder chooses the run-id mechanism. For example, a heartbeat row is opened
  when a job starts, rather than written when it ends, and its id is passed
  down; or a run id is stamped on the dispatch. Old rows keep no parent.
- **The map's edges are config,** derived from the agent YAMLs (`tools:`)
  and a small fixed table of which job feeds which agent. The data supplies
  only the lamps and facts.
- **The analyst's input is stored** with its `runs` row, as text, and is
  pruned with it.
- **Keys and URLs** *(builder check; my call)*:
  - **Jobs:** `/jobs/daily`, `/jobs/alert_poller`, `/jobs/thresholds`,
    `/jobs/uptime`, `/jobs/security`, `/jobs/backup`. These keep today's
    `agent_runs.agent` keys, so stored heartbeats are not renamed.
  - **Agents:** `/agents/analyst`, `/agents/investigator`,
    `/agents/auditor`. The analyst's Models panel moves to
    `/agents/analyst`; the panel table's page key changes, and the stored
    `model_overrides` keys (`daily_analyst`, `investigator`) do not.
  - **Old URLs:** `/agents/daily` → `/agents/analyst` (where the Models
    panel the operator just learned lives), `/agents/security` →
    `/agents/auditor`, and `/agents/alert_poller`, `/thresholds`, `/uptime`
    and `/backup` → `/jobs/<same key>`. These use a **302, not a 301**, so
    a browser never caches a target that might change.
  - The daily run and the security audit are both a job (the schedule) and
    an agent (the model), so their two pages link to each other.

## Constraints

- **design.md is binding:** lamps and words, no emoji in the UI (Telegram
  lines may keep theirs), tracked mono labels, and the one stylesheet capped
  by its test. A new component (the map) is added to design.md on purpose.
- **Writes:** the dashboard's only new writes are pause/resume, through
  `_ACTION_HELPERS`. The daemon stays the sole executor.
- **Heartbeats:** written by the daemon's job wrappers only, as today.
- **Phones:** the map restacks into three stacked lists, and the timeline
  stays one column.
- **Ported modules:** golden modules (`reconcile.py`, `poller_logic.py`,
  `reports/daily_dashboard.py`) stay byte-identical. Causal ids are added in
  the pipelines and the store, not in the golden logic.
- **Testing:** `pytest -q` stays green. New pure logic (timeline assembly,
  pause state) gets unit tests.

## Left to the builder

- The causal-link mechanism (see above), as long as links are recorded, not
  inferred.
- The map's markup: CSS grid or inline SVG, within design.md and the
  stylesheet cap.
- How many tool calls show before "show all" in a timeline row.
- The Overview panel's new layout.

## Calls made without the operator (check these)

- **Pause durations are 1 h, 4 h and 24 h**, with no "until I resume"
  option, because every pause must end by itself.
- **Telegram on pause and on resume**, so a maintenance window is visible
  where the operator already looks.
- **"Paused" (dashboard, temporary) is split from "Off" (config).** Today
  both read "Paused".
- **Which jobs can be paused:** all of them, including the daily run and the
  weekly security audit. A pause that covers a scheduled time skips that run;
  it is not caught up afterwards.
- **The analyst's input is now stored per daily run.** That is tens of KB per
  run, twice a day, pruned with runs (120 days by default), so a few MB.
- **Old `/agents/<job>` URLs redirect (302)** rather than break.
  `/agents/daily` goes to the analyst's page, and `/agents/security` to the
  auditor's.
- **Incident events get their own table**, so "escalated" can sit under the
  run that escalated the incident.
- **Pause and resume Telegram lines come from the daemon's poll cycle**, so
  they arrive within about 5 minutes.
- **Activity uses the existing Live / 24 h / 7 d window switch.**
