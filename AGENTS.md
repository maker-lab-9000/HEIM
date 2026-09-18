# AGENTS.md — HEIM project guide

A single document for anyone (human or AI agent) working on **HEIM — Homelab Event &
Incident Monitor**: what it is, how it's built, the invariants you must not break, how it
integrates, how it scales, and the roadmap of planned improvements.

Companion docs: [`README.md`](README.md) (setup & operation),
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (data flow + n8n→module provenance map).

---

## 1. What HEIM is

HEIM watches a homelab through Prometheus and turns raw metrics into three products:

1. **A twice-daily AI health report** — 49 PromQL range queries over a 3-day window are
   aggregated into a compact payload, analyzed for *degradation trends* by an LLM
   (OpenRouter primary → Anthropic fallback), and delivered as a styled HTML dashboard
   email, a Home Assistant sensor, and a Loki event stream.
2. **Fast-path detection** — a 5-minute poller diffs firing Prometheus alerts against the
   incident store, opening/escalating/resolving incidents between LLM runs.
3. **Approval-gated agentic root-cause investigation** — new or escalated incidents on
   investigable hosts dispatch an AI agent (Claude, native tool calling) that asks for a
   human 👍 over Telegram, then runs read-only diagnostics (guarded SSH, PromQL
   instant/range, metric discovery, Home Assistant API, Proxmox API), and delivers a
   confidence-rated root-cause report with remediation steps — by email, chunked
   Telegram messages, an HA sensor, and Loki events.

It is a **standalone Python port of an n8n workflow stack** ("PAM 10–51"). Every port is
covered by golden tests against the original JavaScript behavior (394 tests). Design
rule: **declarative data in `config/`, pure logic in `src/heim/` with tests, I/O at the
edges** (tools, channels, pipelines).

### Feature inventory

| Area | Features |
|---|---|
| Detection | 49-query trend catalog · per-day averages, change %, warn/crit flags · Prometheus alert rules with `qid` labels (fast path) · anti-flap hysteresis (2 clear polls / 2 missed runs) |
| Incidents | SQLite store · deterministic fingerprints (`host\|qid\|name`) · open/clearing/resolved lifecycle · warn→crit escalation · per-fingerprint dispatch lock · poller-vs-daily ownership split (`[alert]` prefix) · false-positive verdicts + timed/forever suppression (pipeline-level, analyst hint) |
| Agent | Anthropic-native tool loop · soft prompt budget + hard in-loop step cap · retries · real token accounting · output salvage (`## Summary` contract, leaked-tool-call detection) |
| Tools | Guarded read-only SSH · PromQL instant/range with token-compact encoding · metric discovery · GET-allowlisted HA and Proxmox APIs · per-call Telegram live feed + local `audit.jsonl` |
| Human loop | Telegram inline-button approvals (long-poll, no inbound ports) raced against a store-written decision (dashboard/CLI, works with no Telegram at all) · decline/timeout → re-proposed next run · outcome confirm (Resolved / Needs human) |
| Delivery | n8n-faithful HTML dashboard email · investigation report email · chunked Telegram reports · HA sensors (`sensor.pam_*`) · Loki AI-event stream (Grafana-compatible) |
| Ops | `--dry-run` on every pipeline · `heim check` connectivity validation · crash-safe investigation job queue (`heim jobs`, restart sweep, re-trigger with `retry_of`) · Docker/compose deployment (outbound-only, plus the optional dashboard port) · `.env` interpolation for all deployment identity |
| Dashboard | Read-only web UI (`heim dashboard`, FastAPI + Jinja + vendored htmx): overview KPIs, investigations list/filters, the agent-transcript detail page with burn line, incidents, findings history, host cards · optional HTTP basic auth · one SQLite reader (WAL), never a writer |

---

## 2. Working on the repo

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q                    # 394 tests, must stay green
.venv/bin/heim check                   # live connectivity validation
.venv/bin/heim daily --dry-run         # full pipeline, side effects stay local (out/)
docker compose build && docker compose run --rm heim check   # container parity
```

Conventions:
- **Pure logic gets tests.** Anything in `incidents/`, `metrics/`, `guards/`,
  `reports/` is pure (no I/O) and unit-tested. I/O lives in `tools/`, `channels/`,
  `pipelines/`, `runtime.py`.
- **Ported modules are golden.** Files whose docstring names an n8n source node were
  ported line-faithfully, quirks included. Behavior changes there need a deliberate
  decision + updated golden tests + a docstring note — never a silent "cleanup".
- **Config is data.** New hosts/tools/agents/queries are new YAML files, not code edits.
  Deployment identity (IPs, users, ids) is `${VAR}`-interpolated from `.env`; never
  commit a real IP, username, chat id, or address.
- **Fire-and-forget side channels.** Loki/HA/Telegram-feed failures are logged and
  swallowed. Only the core path (metrics → analysis → store → report) may raise.

### Invariants (do not break casually)

1. **Fingerprint stability** — `host|qid|name`, anchored to deterministic metric rows,
   never LLM wording. `qid`s in `config/queries/daily.yaml` must match the `qid` labels
   in `prometheus/alerts.yml`.
2. **Dispatch lock** — `investigated=true` is set when an investigation is *queued*;
   only decline / needs-human / timeout reset it.
3. **Poller ownership** — the poller resolves only `[alert] `-prefixed incidents.
4. **Read-only agent** — every tool is read-only by guard *and* by OS/API privilege.
   Never add a mutating tool without a separate approval design.
5. **Loki schema compatibility** — `job=homelab-ai-monitor`, low-cardinality labels,
   event types `state|incident|finding|category|investigation|action`. The Grafana
   dashboard's LogQL depends on it.
6. **Report contract** — the agent's final message starts with `## Summary`; the
   renderer salvages preambles and flags everything else incomplete with raw output
   preserved. Keep prompt and salvage logic in sync.
7. **HA compatibility** — entity ids stay `sensor.pam_*` (dashboards built for the n8n
   stack read them).

---

## 3. Integrations

### Current

| Integration | Direction | Module | Auth |
|---|---|---|---|
| Prometheus | read (queries, alerts, catalog) | `metrics/`, `tools/prometheus_query`, `pipelines/poller` | none (LAN) |
| Loki | write (AI events) | `channels/loki` | none (LAN) |
| Grafana | indirect (reads Loki/Prometheus) | `grafana/` dashboards | n/a |
| Telegram | bidirectional (notify, live feed, approvals) | `channels/telegram` | bot token |
| SMTP / Gmail | write (reports) | `channels/email` | app password |
| Home Assistant | read (agent tool) + write (report sensors) | `tools/ha_api`, `channels/ha` | non-admin LLAT |
| Proxmox VE | read (agent tool) | `tools/proxmox_api` | auditor-role API token |
| SSH (target hosts) | read-only diagnostics | `tools/ssh_diagnostic` | dedicated key + scoped sudoers |
| Anthropic | agent loop + analyst fallback | `agent/runner`, `llm` | API key |
| OpenRouter | analyst primary | `llm` | API key |

### Adding one

- **New agent tool**: YAML in `config/tools/` (LLM description + arg schema) + a `Tool`
  subclass + a guard (or hard-scoped client) + list it in `config/agents/investigator.yaml`.
- **New delivery channel** (ntfy, Matrix, Discord, webhook…): `channels/<x>.py` with
  fire-and-forget semantics, exposed on `Runtime`, called from pipelines.
- **New host**: `config/hosts/<name>.yaml` (+ OS-side permission set, + entry in
  `instance_host_map`). The host `role` drives brief selection and reconcile gating.

---

## 4. Scalability

Honest assessment of where the current design's limits are:

**What scales fine as-is**
- *Hosts & queries*: both are config files; fetches are concurrent (semaphore 8) and the
  aggregation is O(series). Dozens of hosts / hundreds of queries are a non-issue —
  the practical ceiling is the **analyst prompt size** (the whole payload is one LLM
  input; ~50 queries ≈ tens of KB. Past a few hundred series, shard the daily run per
  host-group or summarize before the LLM).
- *Incidents*: SQLite with one writer (the daemon) is good for orders of magnitude more
  incidents than a homelab produces. WAL is on, so the dashboard reads the same file
  while the daemon writes.
- *Investigations*: run as independent asyncio tasks; each is one agent session. The
  real cost ceiling is LLM tokens, not compute.

**Known limits (accepted for a homelab, fixable if outgrown)**
- **Single process, single executor.** Scheduler, poller, approvals, the queue worker
  and investigations all live in one daemon. A crash mid-investigation still loses that
  *session* — on restart `sweep_interrupted()` marks it failed and the job
  `interrupted` (it is not auto-resumed); the incident's dispatch lock re-proposes it
  after the next decline/timeout cycle. Other processes (dashboard, CLI) may now
  *enqueue* work into the `jobs` table (§5.2), but the daemon stays the only executor.
- **Investigation concurrency** is capped (`max_concurrent_investigations`, default 2 —
  a global semaphore around the agent+delivery phase; approval waits don't hold a slot).
  The queue worker runs one job at a time on top of that cap.
- **One Telegram bot = one getUpdates consumer.** Two daemons on the same token
  conflict. Multi-instance setups need per-instance bots or a webhook receiver.
- **Self-monitoring blind spot** (inherited): HEIM can't alert on the box *it runs on*
  dying. Mitigation: run it on a separate Proxmox guest (done) + a dead-man's switch
  (roadmap §5.7).

---

## 5. Roadmap / possible improvements

Ordered so each stage enables the next. §5.1–§5.3 together are the "self-contained
dashboard" milestone.

### 5.1 Persist investigations & findings (the enabler) — ✅ implemented

Today an investigation leaves only ephemeral traces: emails, Telegram messages,
`audit.jsonl` lines, and Loki events. Everything needed for real tracking already flows
through `agent/runner.py` and the pipelines — it just isn't stored. Add to the SQLite
store (WAL mode):

```
investigations(id, fingerprint, host, host_role, agent_name, model,
               trigger  -- daily | poller | manual | dashboard
               status   -- pending_approval | declined | running | complete |
                           incomplete | needs_human | resolved
               started_at, finished_at,
               input_tokens, output_tokens, n_steps,
               brief_md, report_md, incomplete_reason, outcome_by)

investigation_steps(id, investigation_id, seq, tool, args_json,
                    result_preview, result_bytes, blocked, duration_ms)

findings(id, run_at, source,          -- daily | poller
         host, metric, severity, trend, summary, detail, recommendation,
         fingerprint,                  -- the incident it reconciled into, if any
         verdict)                      -- NULL | confirmed | false_positive
runs(id, run_at, kind, overall, model_used, duration_s, counts_json)
```

Implemented as specced (see `incidents/store.py`, `tests/test_tracking.py`): the runner
records every step (tool, args, preview, size, blocked flag, per-call duration) via an
`on_step` callback, and the pipelines record trigger, status transitions
(pending_approval → declined | running → complete/incomplete/failed → resolved |
needs_human), token totals and the report. `audit.jsonl` stays as the tamper-evident
low-level trail. CLI: `heim investigations [--limit N] [--show ID]`.

### 5.2 Job queue for investigations — ✅ implemented

Make dispatch go through a small `jobs` table instead of bare `asyncio.create_task`:
requested → approved → running → done, with a concurrency semaphore and crash recovery
(on daemon start, re-queue `running` jobs as `interrupted`). This gives: restart-safe
investigations, a re-trigger primitive, and a write path the dashboard can use without
being a second SQLite writer (the daemon polls the queue; the dashboard only inserts).

Shipped: `jobs(kind, payload_json, status, requested_by, retry_of, investigation_id,
error, created_at/started_at/finished_at)` in `incidents/store.py`, claimed atomically
(`BEGIN IMMEDIATE` + `busy_timeout=5000`, so a second writer never double-claims);
`daemon._queue_worker` drains it every 4 s through the normal `run_investigation` path
(cap, approval, tracking and delivery unchanged) and `store.sweep_interrupted()` runs on
daemon start. Enqueue helpers live in `pipelines/queue.py`
(`enqueue_investigation` / `enqueue_retry` / `request_from_payload`); CLI: `heim jobs`.
Scheduled daily/poller dispatch still goes straight to `asyncio.create_task` —
the queue is the path for *requested* work.

### 5.3 The HEIM dashboard (self-contained web UI) — ✅ read-only v1 shipped

Grafana stays for time-series exploration — but it is read-only over Loki and can't
*act*. A proprietary dashboard is justified exactly where actions and rich per-entity
views live. Design:

- **Stack:** FastAPI + Jinja + htmx (no frontend build step, matches the repo's ethos),
  served by the same daemon process (or a `heim dashboard` sidecar) on e.g. `:8300`.
  One new compose port. Reads SQLite directly (WAL); *writes only to the jobs/verdict
  tables* — the daemon remains the sole pipeline writer.
- **Auth:** the container goes from "no inbound ports" to one — keep it LAN/tailnet-only
  and add HTTP basic auth or a static bearer token from `.env`; never expose publicly.
- **Pages** (matching the split you outlined):
  - **Overview** — health tiles (open incidents, pending approvals, running
    investigations, last run, token spend today/month), latest headline.
  - **Hosts** — per-host card: role, open incidents, last findings, quick
    "investigate now" button.
  - **Incidents** — the store, filterable by status/host/severity; per-incident
    timeline (timesSeen, escalations, linked investigations); actions: *re-trigger
    investigation*, *mark false positive*, *resolve manually*.
  - **Findings** — full history from the `findings` table (today they vanish after the
    email); filter by host/severity; verdict buttons (confirm / false positive).
  - **Investigations** — list + detail: trigger source, agent + model, full step
    timeline (tool → command/args → result preview → duration), token usage in/out,
    the rendered report, outcome; *re-run* button (fresh evidence, same brief).
  - **Recommendations** — the union of open incidents' latest recommendations and
    investigation remediation lists, checkable (done/dismissed).
- **Live updates:** htmx polling or SSE from the daemon; investigations stream their
  live feed (the same lines that go to Telegram) into the detail page.

**Shipped (v1, `src/heim/dashboard/`, UI spec in `docs/design/dashboard-ui.md`):** the
read-only half — Overview, Investigations (list + filters + the transcript detail page
with the burn line), Incidents, Findings, Hosts, plus `/healthz`. `heim dashboard
--host --port` (uvicorn) and an optional `dashboard` compose service on `:8300`;
optional HTTP basic auth from `HEIM_DASHBOARD_TOKEN`; htmx used only for filter swaps
and 5 s polling of running investigations. It opens **one SQLite reader** (WAL) and
writes nothing — every action (approve, re-trigger, verdicts, recommendations) is
deliberately deferred to the jobs queue in §5.2, §5.4 and §5.5; the pages reserve their
spots (outcome line, verdict column). Also deferred: the Recommendations page, "load 50
more" pagination (lists cap at 200 rows), and the live Telegram-feed stream.

### 5.4 False-positive handling — ✅ implemented

- `verdict=false_positive` on a finding sets `status=suppressed` on its incident
  (new status) with `muted_until` (or forever). Reconcile and poller skip re-opening
  suppressed fingerprints; the daily email lists suppressed matches in one muted line
  ("2 suppressed") instead of findings.
- Feed the suppression list into the analyst prompt as a short "known false positives —
  do not report unless materially changed" block (bounded, e.g. 10 entries, to protect
  the token budget).
- CLI parity: `heim incidents mute <fingerprint> [--days N]` / `unmute`.

Shipped: a `suppressions(fingerprint, until, reason, created_at)` table plus
`pipelines/suppression.py`, whose **pure** filters (`filter_reconcile`,
`filter_decision`, `filter_incident_events`) are applied *in the pipelines* — the golden
`reconcile.py` / `poller_logic.py` stay byte-identical. A muted fingerprint is never
upserted (so a stored `suppressed` row is neither resurrected nor mutated), dispatched,
notified or emitted as an incident event; the bounded hint is appended to the analyst's
**user** message, not the cached system prompt. `mark_false_positive(store, finding_id,
days)` does verdict + mute + `status=suppressed` in one call; default window
`settings.suppression_days` (90, 0 = forever). Not done: the "2 suppressed" muted line
in the daily email (it would mean editing the golden `reports/daily_dashboard.py`).

### 5.5 Re-trigger & manual trigger — ✅ implemented

`heim investigate --fingerprint <fp>` (pull host/findings from the store instead of
flags) + the dashboard button, both enqueueing via §5.2. Re-triggered runs link to their
predecessor (`investigations.retry_of`) so the detail view can diff "what changed since
last time" — and optionally prepend the prior report's root cause to the brief as
context ("verify whether this earlier conclusion still holds").

Shipped: `heim investigate --fingerprint` runs directly (no queue) off the incident row;
`queue.enqueue_retry(store, investigation_id, requested_by)` re-queues a past
investigation with the same host/role/fingerprint, findings re-synthesized from the
incident row, and threads `retry_of` through `InvestigationRequest` into the new
`investigations` row. Not done: prepending the prior root cause to the brief.

### 5.6 Deeper agent observability

- Per-step token attribution (usage delta per turn) and per-investigation **cost** in
  real currency (model price table in config).
- Store the full message transcript (optional, size-capped) for post-mortems of wrong
  RCAs — today only the salvaged report survives.
- An evaluation harness: replay a stored brief + tool transcripts against a new
  model/prompt and diff the conclusions (the PAM 90 test-bench habit, systematized).
- Self-telemetry: a `/metrics` endpoint (investigations run, tokens, failures,
  approval latency) scraped by the same Prometheus — HEIM watching HEIM.

### 5.7 Smaller, high-value items

- **Dead-man's switch**: ping healthchecks.io (or HA) after each poll; closes the
  "who watches the watcher" gap for real.
- **Investigation concurrency cap** — ✅ implemented (`max_concurrent_investigations`).
- **Web approvals** — ✅ backend implemented: the approval wait races the Telegram
  button against a 5 s poll of `investigations.approval_decision`, which any other
  process may write; the loser is cancelled. With no Telegram configured the store poll
  *is* the gate (a dashboard-only deployment keeps its human in the loop instead of
  silently skipping approval); `--dry-run` still auto-approves. The dashboard's
  approve/decline buttons are the remaining UI half.
- **Retention**: prune resolved incidents/findings/investigation steps after N days;
  vacuum job.
- **Multi-model agent loop**: an OpenAI-compatible tool-calling backend in
  `agent/runner.py` so the investigator can run on OpenRouter models too.
- **More channels**: ntfy/Matrix/Discord via the channel recipe in §3.
- **MCP server**: expose the five guarded tools over MCP so interactive Claude sessions
  can use the same vetted, read-only toolbox as the investigator.
- **Backups**: nightly SQLite `.backup` into `./data/backups/` (it's the only state).

### Non-goals

Mutating remediation tools (restart/cleanup actions) without a dedicated approval &
rollback design; multi-tenant SaaS-ification; replacing Grafana for time-series work.

---

## 6. Notes for AI agents working here

- Read `docs/ARCHITECTURE.md` first; it maps every module to its n8n source node.
- Run `.venv/bin/pytest -q` before and after your change; 394 must not regress.
- Ported modules (docstring names an n8n node) are behavior-frozen — see §2.
- Never log, commit, or email secrets; deployment identity comes from `.env` via
  `${VAR}` interpolation and must stay out of the tree.
- The live deployment is a real homelab: prefer `--dry-run` for verification, and treat
  anything that emails/notifies/dispatches as production.
