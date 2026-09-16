# HEIM architecture

HEIM (Homelab Event & Incident Monitor) is a modular Python re-implementation of the n8n "Prometheus Agentic Monitor"
(PAM 10–51 workflows). Design rule: **declarative data in `config/`, pure logic in
`src/heim/` with tests, I/O at the edges** (tools, channels, pipelines).

## Data flow

### Daily run (`heim daily`, cron in the daemon)
```
queries/daily.yaml ─► fetch 49 query_ranges (3d window, concurrent, per-query neverError)
                  ─► metrics.aggregate       → payload {categories, topAlerts, counts, overall}
                  ─► llm.analyst_complete    → strict-JSON analysis (primary → fallback model)
                  ─► incidents.reconcile     → rows_to_write · summary · to_investigate
                  ─► store.upsert            (SQLite)
                  ─► reports.daily_email     → email channel (or out/*.html)
                  ─► channels.ha             → sensor.pam_report_morning|evening
                  ─► incidents.loki_events + state → channels.loki (one batched push)
                  ─► pipelines.investigate.dispatch_all(to_investigate)
```

### Fast-path poller (`heim poll`, every 5 min in the daemon)
```
GET /api/v1/alerts ─► incidents.poller_logic.diff_and_decide (pure; aborts if Prometheus down)
                   ─► store.upsert · telegram notify · loki events · state emit
                   ─► dispatch_all(new / warn→crit escalations)
```

### Investigation (`heim investigate`, or dispatched by either pipeline)
```
request {host, role, fingerprint, findings}
  ─► brief          = prompts/briefs/<role>.md.j2 (+ temperature playbook when relevant)
  ─► approval       = telegram.ask (inline buttons, 6h timeout) — decline/timeout →
                      store.set_investigated(fp, False)  → re-proposed next run
  ─► system prompt  = prompts/investigator.md.j2 + hosts[].facts + hosts[].privileges
  ─► agent.runner   = Anthropic tool loop over tools listed in agents/investigator.yaml
                      (soft budget in prompt, hard cap in loop, retries, real token usage)
  ─► reports.salvage → trim preamble before '## Summary' / flag incomplete with raw output
  ─► email + telegram chunks (≤3900) + HA sensor + loki investigation/action events
  ─► outcome confirm (✅ Resolved / ⚠️ Needs human, 8h) — needs-human/timeout →
     investigated=False → re-surfaces next run
```

## n8n workflow → module provenance

| n8n workflow / node | Here | Tests |
|---|---|---|
| PAM 10 Build Queries | `config/queries/daily.yaml` + `metrics/queries.py` | test_queries |
| PAM 10 Aggregate & Summarize | `metrics/aggregate.py` | test_aggregate |
| PAM 10 Basic LLM Chain (+ fallback) | `llm.py` + `config/prompts/analyst.md` | — |
| PAM 10 Build Dashboard HTML | `reports/render.daily_email` (lighter template) | test_render |
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
| PAM 40 SSH + Format Output + feed/log | `tools/ssh_diagnostic.py` (audit.jsonl replaces session.log) | — |
| PAM 41 Build Request / Format Result | `metrics/promql.py` | test_promql |
| PAM 42 Guard Path / Call HA API | `guards/ha_guard.py` + `tools/ha_api.py` | test_guards |
| PAM 43 Discover metrics | `metrics/discover.py` + `tools/discover_metrics.py` | test_discover |
| PAM 44 Guard Path / Format Output | `guards/proxmox_guard.py` + `metrics/proxmox_format.py` + `tools/proxmox_api.py` | test_guards, test_proxmox_format |
| PAM 50 Build Loki Payload | `channels/loki.py` | test_integration |
| PAM 51 Compute State | `incidents/state.py` | test_state |
| n8n Data Table `monitor_incidents` | `incidents/store.py` (SQLite, same row schema) | test_integration |
| Schedule triggers | `daemon.py` (APScheduler) / cron / CLI | — |

The original Code-node JS sources were extracted to `reference/` (gitignored) during the
port; the module docstrings name their source nodes and any deliberate divergence.

## Key invariants (do not break casually)

1. **Fingerprint stability** — `host|qid|name` anchored to deterministic metric rows,
   never LLM wording. Changing `qid`s in `queries/daily.yaml` or alert-rule labels breaks
   incident continuity and the dispatch lock.
2. **Poller ownership** — the poller resolves only `[alert] `-prefixed incidents; the
   daily reconcile owns LLM-born trend incidents. Two clear polls / two missed daily runs
   before resolve (anti-flap hysteresis).
3. **Dispatch lock** — `investigated=true` is set when an investigation is *queued*;
   only decline / needs-human / timeout reset it. This is what stops double prompts.
4. **Reads only** — every tool is read-only by construction (guards) and by privilege
   (SSH user, API roles). Never add a mutating tool to the investigator without a
   separate approval design.
5. **Fire-and-forget side channels** — Loki/HA/Telegram-feed failures are logged and
   swallowed; only the core pipeline (metrics → analysis → store → report) may raise.
6. **The agent's final message contract** — must start with `## Summary`; the renderer
   salvages preambles and flags everything else incomplete *with the raw output
   preserved*. Keep prompt and salvage logic in sync.
7. **Loki schema compatibility** — labels/events must stay low-cardinality and match the
   Grafana dashboard's LogQL (`job=homelab-ai-monitor`, selective `| json v=...` extracts).

## Extension recipes

- **New host** → `config/hosts/<name>.yaml` (+ permissions on the host, + entry in
  `instance_host_map`). Role drives brief selection and reconcile gating.
- **New tool** → `config/tools/<name>.yaml` + a `Tool` subclass + add to
  `agents/investigator.yaml:tools`. Guards live in `heim/guards/`; give every new tool a
  guard or a hard-scoped client.
- **New query** → append to `queries/daily.yaml` with a stable `qid`; add a matching
  alert rule (same `qid` label) if you want fast-path detection.
- **Different models** → edit `agents/*.yaml`. The investigator loop is Anthropic-native;
  the analyst accepts any OpenRouter (OpenAI-compatible) model.
- **New delivery channel** → add `channels/<x>.py`, expose it on `Runtime` with
  fire-and-forget semantics, call from the pipelines.
