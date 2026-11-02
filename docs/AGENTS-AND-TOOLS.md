# Agents and tools

HEIM has seven agents. Four detect problems, one investigates them, one audits
configuration and one looks after HEIM's own data. Only the investigator and the
security auditor call an LLM with tools; the daily analysis makes one LLM call without
tools; the rest are plain code.

## Heartbeats

The daemon records one row in `agent_runs` per agent run: start, finish, ok or error,
and a few counters. The Agents page reads these rows to say whether each agent is
working. Only the daemon writes them, so a CLI one-off such as `heim poll` never makes a
dead scheduler look alive. Heartbeats are kept 14 days.

An agent's state is one of: Healthy, Degraded (the run before the last failed), Failed,
Overdue (no run for longer than the cadence plus a margin: three intervals for the poll
agents, an hour for the daily analysis, two hours for the backup, a day for the audit),
Paused (switched off in settings), No data yet. The investigator is event-driven and
reads Running, Idle, Degraded or Failed instead. If one of the three poll agents is
Overdue or has no data, the overview's condition reads Unknown rather than Normal:
silence is not good news.

## The detection agents

All four write to one SQLite incident store. An incident's fingerprint is
`host|qid|name`, anchored to the metric row, never to the model's wording. A prefix on
the incident's name records which path owns it, and each path resolves only its own.

### Alert poller

Every `poll_minutes` (5), reads `/api/v1/alerts` and diffs the firing alerts against the
store. It opens `[alert] ` incidents, escalates warning to critical, and resolves after
two clear polls. If Prometheus is unreachable it changes nothing. New incidents and
escalations go to Telegram and may propose an investigation.

### Threshold watch

In the same poll, evaluates every catalog query against its own `warn`/`crit` bounds
(`threshold_severity` picks which). A series must be over its bound on
`threshold_consecutive` (2) polls in a row before a `[metric] ` incident opens, so a
single spike does not cost an agent run. `heim thresholds` shows each series' value,
flag and streak.

### Uptime monitor

In the same poll, reads Uptime Kuma's `/metrics`. Every unpaused monitor is expected up.
A down monitor opens an `[uptime] ` incident and sends one Telegram message per host.
Hosts HEIM can investigate get an approval-gated investigation; `heim` itself and
addresses that are not HEIM hosts are report-only. A recovery message follows two up
polls. A monitor that goes down again within an hour reopens quietly, with at most one
"keeps flapping" line an hour and a "stable again" line after an hour up. After two
failed reads HEIM says it cannot reach Uptime Kuma instead of guessing. The daily run
ignores `[uptime] ` incidents.

### Daily analysis

At each `schedules.daily` time (07:00 and 22:00), fetches the 50 catalog queries over
three days, folds them into per-host, per-category rows (per-day averages, change,
flags), and sends that payload to the analyst model (OpenRouter primary, Anthropic
fallback) with a strict-JSON contract. The reconciler turns the findings into incidents
(two missed runs before one resolves), and the run produces the HTML email, the
`sensor.pam_report_morning` / `_evening` sensor, findings rows and Loki events. Muted
fingerprints are listed in the analyst's prompt (at most 10) as known false positives.

## The investigator

### Dispatch

A new or escalated incident on an investigable host (its `investigable` categories)
proposes an investigation. The dashboard (Investigate, Re-run) and `heim investigate`
start one by hand. Requests from the dashboard and re-runs go through the `jobs` queue,
which the daemon drains every 4 seconds. Setting `investigated=true` on the incident when
the investigation is queued is the dispatch lock: it stops a second prompt. Only a
decline, a needs-human answer or a timeout clears it.

### Approval

The brief is rendered first, from the host role's template, and stored with the
investigation, so whoever decides sees exactly what the agent will be asked. Then HEIM
asks:

- on Telegram, with inline buttons (if Telegram is configured), and
- on the dashboard, through the investigation's Approve and Decline buttons.

Whichever answers first wins. With `approve_timeout_hours: 0` (the default) the wait has
no deadline. A pending approval survives a restart: the daemon re-arms it with the same
id and the same buttons, and a Telegram tap is written to the store, so a later process
still sees it. Waiting for approval does not take one of the
`max_concurrent_investigations` slots. A decline returns the incident to the pool and it
is proposed again on a later run. `--dry-run` approves automatically, and
`approvals.require: false` or `--no-approval` skips the gate.

### The tool loop

The investigator is an Anthropic tool-calling loop (`agent/runner.py`). The system
prompt is `investigator.md.j2` plus the host's `facts` and `privileges`. The model is told
to finish within `soft_step_budget` (15) calls; at `hard_step_cap` (25) the loop refuses
further calls and makes it write the report. The runner retries API errors, records real
token usage per run and per turn, prices it from `model_prices`, and records every step
(tool, arguments, result preview, size, blocked flag, duration).

### The report

The final message must start with `## Summary`, followed by the investigation steps,
the root cause with a confidence level, and recommended remediation. If the model writes
a preamble, the renderer cuts it; anything else without a summary is marked incomplete
and the raw output is kept. The report goes out by email, as Telegram messages (split
under 3,900 characters), as the `sensor.pam_investigation_<host>` sensor, as Loki events,
and to the dashboard.

### Outcome

After delivery, Telegram asks for the outcome: Resolved (handled) or Needs human. Needs
human, or no answer within `outcome_timeout_hours` (8), clears the dispatch lock so the
incident comes back. This prompt is Telegram-only and is not re-armed after a restart;
the investigation simply stays complete.

## Tools and guards

| Tool | Reads | Guard |
|---|---|---|
| `ssh_diagnostic` | a shell command on a host with an `ssh:` block | `guards/command_guard.py`: a segment-aware read-only gate that blocks destructive binaries, shell escapes, redirection, nested interpreters and mutating subcommands. The SSH user's sudoers is the real boundary. |
| `prometheus_query` | PromQL, instant or range | read-only API; results are compacted to save tokens |
| `discover_metrics` | metric names and label sets | read-only API |
| `loki_query` | LogQL over the journal of `homelab`, `ubuntu-server` and Home Assistant OS, and `ubuntu-server` container logs | Loki's query API is GET-only; lookback capped at 7 days |
| `ha_api` | Home Assistant REST | `guards/ha_guard.py` GET path allowlist; non-admin token |
| `proxmox_api` | Proxmox VE API | `guards/proxmox_guard.py` GET path allowlist; auditor-role token |

Every call is appended to the local `audit.jsonl` and, with Telegram configured, sent to
the live feed. Tool output is clipped (8 KB). No tool can change anything, by guard and
by OS or API privilege. A mutating tool would need its own approval design first.

Everything the agent reads ends up in emails, Telegram, Loki and the LLM provider's API.
That is the design, so do not give the agent read access to secrets.

## Tooling feedback

The investigator's prompt allows an optional last section, `## Tooling feedback`: zero to
three `tool_name: suggestion` lines about what would have made this investigation faster
or more certain. The section stays in the report. HEIM also extracts it into the
`tool_feedback` table, for complete and incomplete runs. The overview's tool-usage card
shows, under each tool's row, the latest suggestion with a link to its investigation. A
suggestion that names no known tool appears as a general note, because that usually
means the prompt has drifted.

Each tool-calling agent's page (`/agents/investigator`, `/agents/security`) shows its
last 50 tool calls with a per-tool summary of calls, blocked calls and average duration.

## The security audit

Weekly (`schedules.security_audit`, Monday 06:00), read-only. Deterministic code runs
the 47 checks in `config/security/checks.yaml` over the Proxmox API, Home Assistant,
Prometheus and fixed, guard-checked SSH lines. Each result gets a fingerprint
`host|check_id|subject`, and the run is compared with the previous real run: new,
persisting, resolved, carried. Then one bounded model pass (Claude Opus, tools
`prometheus_query`, `discover_metrics`, `loki_query`, `proxmox_api`, no SSH, cap 6) explains and
prioritises the results in an `## AI assessment` appendix. It never decides what is a
finding. It ends with `## Audit feedback`: what limited this run and which checks are
worth adding, shown on the Security page as proposals. If the model fails, only the
appendix is lost. Results go by email, a Telegram digest (with a line for new criticals),
`sensor.pam_security_audit` and Loki. `heim security-audit --dry-run` is stored apart and
never becomes the comparison baseline; `--no-llm` skips the model.

## The backup verifier

Nightly at 03:30: a WAL-safe snapshot of the SQLite store, rotation to `backup_keep`,
then the retention prune. A failed backup skips the prune. Its heartbeat names the file
written. Details in [OPERATIONS.md](OPERATIONS.md#backups-and-retention).

## The human's controls

- Approve or decline an investigation (Telegram or dashboard).
- Confirm the outcome: Resolved or Needs human (Telegram).
- Judge a finding: Confirmed or False positive. A false positive mutes the fingerprint
  for `suppression_days` and sets its incident to `suppressed`; muted fingerprints are
  not reopened, dispatched or notified. Pressing the chosen verdict again clears it, and
  leaving False positive lifts the mute.
- Mute or unmute an incident (dashboard, or `heim incidents mute|unmute`).
- Mark a recommendation Done or Dismiss; pressing it again reopens it.
- Re-run an investigation with fresh evidence, or start one on any configured host.
