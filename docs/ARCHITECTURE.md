# HEIM architecture

HEIM is a Python re-implementation of an n8n workflow stack, the "Prometheus Agentic
Monitor" (PAM 10–51), grown since into seven agents and a web dashboard. The design rule:
**declarative data in `config/`, pure logic in `src/heim/` with tests, I/O at the
edges** (tools, channels, pipelines). The rules for changing it are in
[`AGENTS.md`](../AGENTS.md).

## Processes

- **The daemon** (`heim daemon`, `daemon.py`): one asyncio process with an APScheduler.
  It runs the daily analysis, the poll cycle, the nightly backup and the weekly audit,
  drains the job queue, listens for Telegram taps, and is the only writer of the
  pipeline tables and of the `agent_runs` heartbeats.
- **The dashboard** (`heim dashboard`, `dashboard/app.py`): FastAPI over the same SQLite
  file (WAL). Reads everything; writes only action rows (jobs, approval decisions,
  verdicts, suppressions, recommendation marks).
- **The CLI** (`cli.py`): one-off runs of each pipeline, plus inspection commands.

On start the daemon sweeps interrupted work (`store.sweep_interrupted`), starts the
Telegram consumer, re-arms parked approvals (`rearm_pending_approvals`), then starts the
scheduler and the queue worker.

## Data flow

### Poll cycle (every `poll_minutes`)
```
pipelines.poller.run_poll
  ├─ alerts:     GET /api/v1/alerts ─► incidents.poller_logic.diff_and_decide (pure)
  │              ─► suppression filter ─► store.upsert · Telegram · Loki ─► dispatch
  ├─ thresholds: catalog queries ─► pipelines.thresholds (streaks, [metric] incidents)
  │              ─► store.upsert ─► dispatch
  └─ uptime:     Uptime Kuma /metrics ─► incidents.uptime_logic (pure, [uptime] incidents,
                 flap handling) ─► store · one Telegram message per host ─► dispatch
daemon: one agent_runs heartbeat per poll half ─► channels.deadman.ping
```

### Daily run (`schedules.daily`)
```
config/queries/daily.yaml ─► 50 query_range fetches (3 d window, concurrent)
  ─► metrics.aggregate       → payload {categories, topAlerts, counts, overall}
  ─► llm.analyst_complete    → strict-JSON analysis (OpenRouter → Anthropic fallback),
                               muted fingerprints appended as a hint
  ─► incidents.reconcile     → rows · summary · to_investigate (pure)
  ─► store.upsert · insert_run · insert_findings
  ─► reports.daily_dashboard → email (or out/*.html)
  ─► channels.ha (sensor.pam_report_*) · incidents.loki_events + state → channels.loki
  ─► pipelines.investigate.dispatch_all(to_investigate)
```

### Investigation
```
request {host, role, fingerprint, findings}   (poll, daily, jobs queue, CLI)
  ─► brief = prompts/briefs/<role>.md.j2, stored on the investigations row
  ─► approval: Telegram buttons raced against investigations.approval_decision
     (dashboard); no deadline by default; decline → dispatch lock cleared
  ─► system prompt = prompts/investigator.md.j2 + host facts + privileges
  ─► agent.runner: Anthropic tool loop over agents/investigator.yaml tools
     (soft budget, hard cap, retries, per-turn tokens, on_step → investigation_steps)
  ─► reports.render.salvage ('## Summary' contract) · extract_tool_feedback → tool_feedback
  ─► email · Telegram chunks · sensor.pam_investigation_<host> · Loki
  ─► outcome confirm on Telegram (Resolved / Needs human)
```

### Weekly security audit (`schedules.security_audit`)
```
config/security/checks.yaml ─► security.catalogue (every read validated by the guards)
  ─► pipelines.security_sources.collect_evidence (PVE GET, HA, PromQL, fixed SSH lines)
  ─► security.evaluate (pure) ─► security.diff vs the last real run
  ─► store: runs(kind=security_audit) + findings(source=security_audit)
  ─► security.report (model-free '## Summary' report)
  ─► agent.runner over agents/security_auditor.yaml → '## AI assessment' + '## Audit feedback'
  ─► email · Telegram digest · sensor.pam_security_audit · Loki
```

### Nightly housekeeping (03:30)
```
store.backup_to(backups/heim-YYYYMMDD.sqlite3) ─► rotate ─► store.prune ─► heartbeat
```

## Module map

| Package | Contents |
|---|---|
| `config.py`, `runtime.py` | pydantic models and loader for `config/` with `${VAR}` interpolation; wiring of store, channels and dry-run |
| `daemon.py`, `cli.py` | scheduler, job worker, housekeeping; the `heim` command |
| `agents.py` | pure model of the seven agents: specs, status from heartbeats, run strips, condition |
| `llm.py`, `costing.py` | analyst completion with fallback; pure cost math |
| `agent/` | `runner.py` (tool loop), `cassette.py` (recorded results for replay) |
| `tools/` | `base.py` (Tool, ToolContext with feed and audit) and one module per tool |
| `guards/` | `command_guard.py`, `ha_guard.py`, `proxmox_guard.py` |
| `incidents/` | `store.py` (SQLite), `reconcile.py`, `poller_logic.py`, `uptime_logic.py`, `state.py`, `loki_events.py`, `types.py` |
| `metrics/` | query catalog, aggregation, PromQL tool encoding, discovery, Proxmox formatting |
| `pipelines/` | `daily`, `poller`, `thresholds`, `uptime`, `investigate`, `queue`, `suppression`, `replay`, `security_audit`, `security_sources` |
| `security/` | pure audit catalogue, evaluators, diff and report |
| `reports/` | salvage and section extraction, the daily dashboard email, templates |
| `channels/` | `telegram`, `email`, `ha`, `loki`, `deadman` |
| `dashboard/` | `app.py` (routes, reads, actions), `format.py` (formatting and the colour code), `recommendations.py`, templates, static |

## Store tables

`incidents` (the n8n data table's schema), `suppressions`, `findings`, `runs`,
`investigations`, `investigation_steps`, `tool_feedback`, `jobs`, `agent_runs`,
`recommendation_states`, `threshold_streaks`, `uptime_monitors` and `uptime_source`. All in one SQLite file in WAL mode.

## n8n workflow to module provenance

| n8n workflow / node | Here | Tests |
|---|---|---|
| PAM 10 Build Queries | `config/queries/daily.yaml` + `metrics/queries.py` | test_queries |
| PAM 10 Aggregate & Summarize | `metrics/aggregate.py` | test_aggregate |
| PAM 10 Basic LLM Chain (+ fallback) | `llm.py` + `config/prompts/analyst.md` | — |
| PAM 10 Build Dashboard HTML + Add Incident Band | `reports/daily_dashboard.py` | test_daily_dashboard |
| PAM 10 Findings/Incidents → Loki | `incidents/loki_events.py` | test_integration |
| PAM 10 Format report for HA / Send to HA | `pipelines/daily._ha_report_md` + `channels/ha.py` | — |
| PAM 11 Diff & Decide | `incidents/poller_logic.py` | test_poller_logic |
| PAM 20 Build Brief | `config/prompts/briefs/*.j2` + `pipelines/investigate.findings_text` | test_integration |
| PAM 20 Ask Approval / Confirm Outcome | `channels/telegram.Telegram.ask` | — |
| PAM 20 Investigator (LangChain agent) | `agent/runner.py` (Anthropic-native) | — |
| PAM 20 Render Report (salvage) | `reports/render.salvage` | test_render |
| PAM 20 Split Report for Telegram | `channels/telegram.chunk_text` | test_render |
| PAM 20 Investigation To Loki | `reports/render.extract_sections` + pipeline | test_render |
| PAM 30 Reconcile Incidents | `incidents/reconcile.py` | test_reconcile |
| PAM 40 Guard Command | `guards/command_guard.py` | test_guards |
| PAM 40 SSH + Format Output + feed/log | `tools/ssh_diagnostic.py` | — |
| PAM 41 Build Request / Format Result | `metrics/promql.py` | test_promql |
| PAM 42 Guard Path / Call HA API | `guards/ha_guard.py` + `tools/ha_api.py` | test_guards |
| PAM 43 Discover metrics | `metrics/discover.py` + `tools/discover_metrics.py` | test_discover |
| PAM 44 Guard Path / Format Output | `guards/proxmox_guard.py` + `metrics/proxmox_format.py` + `tools/proxmox_api.py` | test_guards, test_proxmox_format |
| PAM 50 Build Loki Payload | `channels/loki.py` | test_integration |
| PAM 51 Compute State | `incidents/state.py` | test_state |
| n8n Data Table `monitor_incidents` | `incidents/store.py` | test_integration |
| Schedule triggers | `daemon.py` | — |

New since the port, with no n8n source: threshold watch, the Uptime Kuma source, the
`loki_query` tool, the job queue, durable approvals, suppressions, replay, the security
audit, the agent heartbeats and the dashboard.

The module docstrings name their source nodes and any deliberate divergence. Ported
modules are behaviour-frozen (see `AGENTS.md` §2).

## What stayed the same as n8n

- Incident semantics: fingerprints, two-missed-runs hysteresis, warn-to-crit escalation,
  decline and re-propose, the dispatch lock, the `[alert] ` ownership split. Ported
  line for line with golden tests.
- The guards, output clipping and Proxmox task-list compaction.
- Token-compact PromQL results for the agent.
- The prompts, including the `## Summary` contract and its salvage rules.
- The Loki event schema, so the Grafana "Homelab AI Operations" dashboard works
  unchanged.
- Fire-and-forget side channels: Loki, HA and Telegram failures never sink a run.

## What changed

- Native tool calling (Anthropic API) instead of LangChain scratchpad text; the salvage
  logic stays as a second line.
- Real token accounting from API usage, and cost from a price table.
- Telegram approvals with inline buttons over long polling: no webhook, no inbound
  port. Approvals survive a restart.
- A hard step cap in the loop: the model is made to write its report instead of the run
  being lost.
- The SSH tool writes its audit trail locally (`audit.jsonl`) instead of appending to a
  `session.log` on the target host.
- `metricsSnapshot` (always empty in n8n) was dropped from the investigation inputs.
