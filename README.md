# HEIM — Homelab Event & Incident Monitor

**HEIM** (German: *home*) is a standalone Python port of the n8n **Prometheus Agentic Monitor** stack: a daily AI-written
health report over your Prometheus metrics, plus an **approval-gated agentic investigator**
that SSHes into the affected host (read-only, guarded), queries Prometheus/Home Assistant/
Proxmox live, and delivers a confidence-rated root-cause report — by email, Telegram, Home
Assistant sensors, and a Loki event stream that feeds the existing Grafana dashboard.

Everything the n8n version encoded in workflow JSON is now **declarative config + tested
code**: hosts, tools, agents, prompts, and the PromQL catalog are one file each, so
extending the system means adding a file — not editing a Code node inside an export.

```
┌────────────┐   cron 07:00/22:00   ┌─────────────────────────────────────────┐
│            ├─────────────────────►│ daily: 49 PromQL ranges → aggregate →   │──► email
│   daemon   │                      │ LLM trend analysis → reconcile incidents│──► HA sensor
│ (or cron / │   every 5 min        └───────────────┬─────────────────────────┘──► Loki
│  CLI runs) ├─────────────────────►┌───────────────┴─────────────────────────┐
│            │                      │ poller: /api/v1/alerts → diff → upsert  │──► Telegram
└────────────┘                      └───────────────┬─────────────────────────┘
                                         new / escalated incidents
                                                    ▼
                                    ┌─────────────────────────────────────────┐
                                    │ investigation: Telegram approval →      │
                                    │ agent loop (Claude + 5 guarded tools) → │──► email/TG/HA/Loki
                                    │ salvage/render → outcome confirm        │
                                    └─────────────────────────────────────────┘
```

---

## Project structure

```
heim/
├── pyproject.toml                  # package + deps; installs the `heim` CLI
├── .env.example                    # secrets template (API keys, tokens) → copy to .env
├── config/                         # ← ALL declarative configuration
│   ├── settings.example.yaml       #   endpoints, schedules, recipients → copy to settings.yaml
│   ├── settings.yaml               #   your deployment values (gitignored)
│   ├── hosts/                      #   ← one file per monitored host
│   │   ├── ubuntu-server.yaml      #     role: guest · ssh access · prompt facts · privileges
│   │   ├── homelab.yaml            #     role: hypervisor · Proxmox API · investigable categories
│   │   └── home-assistant.yaml     #     role: ha-guest · HA API
│   ├── tools/                      #   ← one file per agent tool (LLM description + arg schema)
│   │   ├── ssh_diagnostic.yaml     #     guarded read-only shell on an SSH host
│   │   ├── prometheus_query.yaml   #     instant + range PromQL, token-compact results
│   │   ├── discover_metrics.yaml   #     metric-name/label-set discovery
│   │   ├── ha_api.yaml             #     GET-allowlisted Home Assistant REST
│   │   └── proxmox_api.yaml        #     GET-allowlisted Proxmox VE API
│   ├── agents/
│   │   ├── investigator.yaml       #   model, step budget, tool list, prompt template
│   │   └── daily_analyst.yaml      #   primary model (OpenRouter) + fallback (Anthropic)
│   ├── prompts/                    #   ← jinja2 prompt templates
│   │   ├── analyst.md              #     daily analyst system prompt (strict-JSON contract)
│   │   ├── investigator.md.j2      #     investigator system prompt; facts/privileges injected
│   │   └── briefs/                 #     per-host-role investigation briefs
│   │       ├── guest.md.j2  ·  hypervisor.md.j2  ·  ha-guest.md.j2
│   │       ├── _report_spec.md  ·  _temperature_playbook.md.j2
│   └── queries/daily.yaml          #   the 49-query PromQL catalog (qid, thresholds, category)
├── src/heim/
│   ├── config.py                   # pydantic models + loader for everything under config/
│   ├── runtime.py                  # wiring: store + channels + dry-run behavior
│   ├── llm.py                      # analyst completion (OpenRouter primary → Anthropic fallback)
│   ├── cli.py                      # `heim check|daily|poll|investigate|incidents|daemon`
│   ├── daemon.py                   # APScheduler cron/interval jobs
│   ├── agent/runner.py             # the Anthropic tool-use loop (budget, retries, real tokens)
│   ├── tools/                      # tool framework + one module per tool
│   │   ├── base.py                 #   Tool base class, ToolContext (feed/audit), registry
│   │   └── ssh_diagnostic.py · prometheus_query.py · discover_metrics.py · ha_api.py · proxmox_api.py
│   ├── guards/                     # safety guards (ported from n8n, 119 tests)
│   │   ├── command_guard.py        #   segment-aware read-only shell-command gate
│   │   ├── ha_guard.py · proxmox_guard.py   # GET path allowlists
│   ├── incidents/
│   │   ├── types.py                #   HostRouting, ReconcileResult, PollerDecision
│   │   ├── store.py                #   SQLite incident store (was the n8n Data Table)
│   │   ├── reconcile.py            #   pure incident reconciler (fingerprints, hysteresis, locks)
│   │   ├── poller_logic.py         #   pure alert-poller diff
│   │   ├── state.py                #   dashboard state snapshot (healthScore, risk)
│   │   └── loki_events.py          #   finding/category/incident event builders
│   ├── metrics/
│   │   ├── queries.py              #   query catalog loader + 3-day window
│   │   ├── aggregate.py            #   fold query_range results into the analyst payload
│   │   ├── promql.py               #   agent-tool range params + token-compact encoding
│   │   ├── discover.py             #   metric-catalog filtering
│   │   └── proxmox_format.py       #   Proxmox response compaction (tasks lists)
│   ├── channels/
│   │   ├── telegram.py             #   notify, live feed, chunked reports, INLINE-BUTTON approvals
│   │   ├── email.py                #   SMTP HTML delivery
│   │   ├── ha.py                   #   sensor.pam_* pushes
│   │   └── loki.py                 #   batched event push (same schema as the n8n stack)
│   ├── reports/
│   │   ├── render.py               #   salvage logic + markdown→styled-HTML emails
│   │   └── templates/              #   investigation.html.j2 · daily.html.j2
│   └── pipelines/
│       ├── daily.py                #   the daily run (was n8n PAM 10)
│       ├── poller.py               #   the fast-path poller (was PAM 11)
│       └── investigate.py          #   the approval-gated investigation (was PAM 20)
├── tests/                          # 264 tests, incl. faithful-port golden cases
└── docs/ARCHITECTURE.md            # design, data flow, n8n→module provenance map
```

---

## Quick start

```bash
git clone <this repo> && cd heim
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

cp .env.example .env                              # fill in secrets (at least ANTHROPIC_API_KEY)
cp config/settings.example.yaml config/settings.yaml   # set your endpoints / chat id / email
# edit config/hosts/*.yaml — SSH user/key, API endpoints, or delete hosts you don't have

.venv/bin/heim check                               # validates config + connectivity, per item
```

Then try it — every command supports `--dry-run` (emails become HTML files under `out/`,
Telegram/Loki/HA sends become log lines, approvals auto-granted):

```bash
heim daily --dry-run                # full daily run: metrics → LLM → report in out/*.html
heim poll --dry-run                 # one alert-poller cycle
heim investigate --host ubuntu-server --dry-run \
    --finding "memory used climbed 31% → 43% over 3 days, swap growing"
heim incidents                      # show the incident store
heim daemon                         # the real thing: schedules + poller + approval listener
```

### Run it as a service (on your homeserver)

```ini
# /etc/systemd/system/heim.service
[Unit]
Description=HEIM - Homelab Event & Incident Monitor
After=network-online.target

[Service]
User=heim
WorkingDirectory=/opt/heim
ExecStart=/opt/heim/.venv/bin/heim daemon
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now heim
journalctl -u heim -f
```

---

## Configuration reference

### `config/settings.yaml`
Endpoints, schedules, recipients, timeouts — see the commented
[`settings.example.yaml`](config/settings.example.yaml). Every optional block
(`loki`, `telegram`, `email`, `home_assistant`) can be **removed entirely** to disable
that channel; the pipelines degrade gracefully (e.g. no email config → reports are
written to `out/`).

### `config/hosts/*.yaml` — add a host, add a file
| Field | Meaning |
|---|---|
| `role` | `guest` (SSH-reachable, fully investigable) · `hypervisor` (investigated from the guest side + its own API) · `ha-guest` (API only) |
| `investigable` | `all`, or a category list (`[cpu, memory, temperature, disk, diskHealth]`) — gates which findings trigger investigations |
| `ssh` | host/port/user/key for `role: guest` (key path overridable via `HEIM_SSH_KEY`) |
| `api` | base URL (+ `verify_ssl`) for hypervisor / ha-guest hosts |
| `facts` | injected verbatim into the investigator's `[FACTS]` prompt block — topology truths the agent must know |
| `privileges` | injected into `[PRIVILEGES]` — keep in sync with the host's actual sudoers/groups |

To add a second SSH host: create the YAML (`role: guest` + `ssh:`), grant the same
read-only permission set on the host (see *Security*), and add its address to
`instance_host_map` in settings. The reconciler and poller pick it up automatically.

### `config/tools/*.yaml` — add a tool, add a file + a class
`name`, LLM-facing `description`, JSON-schema `args`/`required`, `options` (host binding,
clip bytes), and `module: pam.tools.mymod:MyTool`. The class implements
`async def run(self, args) -> str` — see [`src/heim/tools/base.py`](src/heim/tools/base.py).
List the tool's name in an agent's YAML and it's live.

### `config/agents/*.yaml`
The **investigator**: Anthropic model id, `soft_step_budget` (told to the model),
`hard_step_cap` (enforced by the loop — past it, tool calls are refused and the model is
told to write the report), prompt template, tool list. The **analyst**
(`kind: analyst`): primary + fallback model refs and the strict-JSON prompt.

### `config/queries/daily.yaml`
The 49-query catalog (qid, category, label, unit, direction, warn/crit thresholds,
verbatim PromQL) + the 3-day/3h window. Add or trim queries freely — `qid` is the stable
identity used in incident fingerprints and alert-rule labels, so keep qids stable and
matching your `prometheus/alerts.yml` labels.

---

## What's deliberately the same as the n8n stack

- **Incident semantics** — fingerprints (`host|qid|name`, name-weighted anchoring),
  2-missed-runs close hysteresis, warn→crit escalation re-queue, decline → re-propose,
  per-fingerprint dispatch lock, `[alert]`-prefix ownership split between poller and
  daily reconcile. Ported line-for-line with golden tests.
- **The guards** — the segment-aware read-only command gate, the HA/Proxmox GET
  allowlists, output clipping, the Proxmox task-list compaction (119 tests).
- **Token-compact PromQL results** for the agent (stepSec/offsetsSec encodings, shared
  labels, cAdvisor noise pruning).
- **The prompts** — analyst, investigator (facts/privileges/budget/output contract),
  per-role briefs, temperature playbook, report spec — including the `## Summary`
  requirement and the salvage rules learned in production.
- **The Loki event schema** (`job=homelab-ai-monitor`; `state`/`incident`/`finding`/
  `category`/`investigation`/`action`) — the existing Grafana **Homelab AI Operations**
  dashboard works unchanged.
- **Fire-and-forget side effects** — Loki/HA/Telegram pushes can never sink a run.

## What's deliberately better

- **Native tool calling** (Anthropic API) instead of LangChain scratchpad text — the
  "model leaked its tool call as text" failure class is gone at this layer; the salvage
  logic remains as defense in depth.
- **Real token accounting** from API usage (the n8n footer was a chars/4 estimate).
- **Real Telegram approvals** — inline callback buttons over long-polling; no
  `/webhook-waiting` exposure, no tunnel path-scoping, works fully inside the LAN.
- **Hard budget enforcement in the loop** — a budget overrun can no longer discard the
  whole analysis; the model is forced to write the report with what it has.
- **Everything testable** — 264 tests, including the pure reconcile/poller/aggregate
  logic that lived untested inside Code nodes.

## Divergences to know about (v0.1)

- The daily email is a **lighter template** than the n8n dashboard email (status header,
  incident band, categories, findings, top alerts, watchlist — but no per-host filesystem
  bars or full metric tables yet).
- The SSH tool writes the audit trail **locally** (`audit.jsonl`) + the Telegram feed;
  the remote `session.log` append on the target host was dropped.
- Approval prompts don't survive a daemon restart (an in-flight approval is lost; the
  incident stays `investigated=true` until the decline/timeout path resets it — worst
  case it's re-proposed after the next resolve/decline cycle).
- `metricsSnapshot` (always `{}` in the n8n version too) was dropped from the
  investigation inputs.

---

## Security

The investigator executes **model-authored commands** on your host. The layered defenses
are ported intact, but the OS boundary is the one that matters:

1. **Dedicated SSH user** (e.g. `n8n-monitoring-agent`) with a scoped, read-only sudoers
   allowlist (`du, df, findmnt, lsof, ls, ss, agent-docker`), `systemd-journal`+`adm`
   groups, `kernel.dmesg_restrict=0`, and the root-owned read-only `agent-docker`
   wrapper. Full rationale and setup: the n8n repo's README *Setup step 7* — the
   permission set is identical, and `config/hosts/ubuntu-server.yaml`'s `privileges`
   block must match what you actually grant.
2. **The command guard** blocks destructive binaries, shell escapes, redirection, nested
   interpreters, and mutating subcommands of dual-use tools — defense in depth, not the
   boundary.
3. **API tools** are GET-allowlisted client-side and least-privilege server-side
   (non-admin HA user; auditor-role Proxmox token).
4. Everything the agent sees flows into emails/Telegram/Loki/the LLM API — that's the
   design, so don't grant it read access to secrets (`sudo cat`/`sudo grep` stay
   excluded).

---

## Costs

The only paid component is LLM tokens: one analyst completion per daily run (primary can
be a free OpenRouter model) and one investigator session (typically 10–15 tool calls,
Claude Sonnet) per approved investigation. Real usage is printed in every report footer.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module map, data flow, and the
n8n-workflow → module provenance table.
