# Configuration

All configuration is data under `config/`, plus `.env` for deployment identity and
secrets. Adding a host, a tool, an agent or a query means adding or editing a YAML file.

## `.env`: identity and secrets

Every file under `config/`, and the prompt templates, may use `${VAR}` and
`${VAR:-default}`. The values come from the environment at load time, so IPs, users,
chat ids and addresses live in `.env` and never in git. A reference with no default
whose variable is unset fails at startup, naming the variable and the file. In Docker,
compose injects `.env` through `env_file`, so the same file works in and out of the
container. [`.env.example`](../.env.example) lists everything.

Deployment identity:

| Variable | Used for |
|---|---|
| `HEIM_SERVER_IP` | Prometheus and Loki URLs, the SSH target, instance-to-host mapping |
| `HEIM_PROXMOX_IP` | Proxmox API URL, prompt examples, mapping |
| `HEIM_HA_IP` | Home Assistant URL, mapping |
| `HEIM_OBSERVABILITY_IP` | the guest HEIM runs on (host `heim`), mapping |
| `HEIM_JELLYFIN_IP`, `HEIM_LLM_IP` | the LXC containers (hosts `jellyfin`, `llm`), mapping; optional, an unset one is dropped from the map |
| `HEIM_SSH_USER` | the read-only SSH user (default `monitoring-agent`) |
| `HEIM_TELEGRAM_CHAT_ID` | approval and report chat |
| `HEIM_EMAIL_TO`, `HEIM_EMAIL_FROM` | report delivery |
| `HEIM_UPTIME_KUMA_URL` | Uptime Kuma base URL; empty turns the source off |
| `HEIM_DEADMAN_URL` | dead-man's switch ping URL; empty turns it off |
| `HEIM_AUDIT_EXPECTED_PORTS` | reviewed listening ports for the security audit, `port[:label]` comma-separated |
| `HEIM_GITHUB_REPO` | repository (`owner/name`) for tooling-feedback issues; empty turns it off |
| `HEIM_DASHBOARD_TOKEN` | password for the dashboard's HTTP basic auth; empty means no auth |
| `HEIM_SSH_KEY_FILE` | compose only: host path of the agent's SSH key |
| `HEIM_SSH_KEY`, `HEIM_CONFIG` | override the SSH key path and the config directory |

Secrets: `ANTHROPIC_API_KEY` (required), `OPENROUTER_API_KEY`, `UPTIME_KUMA`,
`TELEGRAM_BOT_TOKEN`, `SMTP_USER`, `SMTP_PASSWORD`, `HA_TOKEN`, `HA_PUSH_TOKEN`,
`PROXMOX_TOKEN`, `HEIM_GITHUB_READ_TOKEN` (Issues: read, for the agents' tool) and
`HEIM_GITHUB_TOKEN` (Issues: read and write, for the daemon's poster), each a
fine-grained token limited to that one repository. Secrets never go in YAML.

## `config/settings.yaml`

Optional. Without it HEIM loads the commented
[`settings.example.yaml`](../config/settings.example.yaml), which takes everything
deployment-specific from `.env`. Copy it when you want to change structure.

- **Endpoints.** `prometheus.url` is required. `loki`, `telegram`, `email` and
  `home_assistant` are optional blocks: remove one to turn that channel off. Without
  `email`, reports are written to `out/`.
- **`schedules`.** `daily` (default `["07:00", "22:00"]`), `poll_minutes` (5) and
  `security_audit` (`"mon 06:00"`). The audit default applies even when the key is
  missing; set `security_audit: ""` to turn it off. `log_digest` (`"08:00"`) emails the
  daily Loki error digest and needs the `loki` block; `""` turns it off. Times use
  `timezone`.
- **`log_digest.yaml`.** The digest's LogQL sources (journal errors on every host, the
  ubuntu-server containers' error-like lines, Home Assistant's `ERROR` lines) and its
  `ignore` list: Python regexes for expected noise (the smartctl low-power lines,
  browserless stats, stack frames). Ignored lines are counted in the email, not hidden.
  `heim check` does not read it; `heim log-digest --dry-run` does.
- **`approvals`.** `require` (true), `approve_timeout_hours` (0 = wait until someone
  answers, the default; a positive value expires into a decline) and
  `outcome_timeout_hours` (8; 0 = wait).
- **Store and logs.** `db_path` (`heim.sqlite3`), `audit_log` (`audit.jsonl`), both
  relative to the working directory (`/data` in Docker).
- **Limits.** `max_concurrent_investigations` (2; waiting for approval does not take a
  slot), `suppression_days` (90; the default mute for a false positive, 0 = forever).
- **Housekeeping.** `deadman_url`, `backup_keep` (14), `retention_days` (120, 0 = keep
  forever). See [OPERATIONS.md](OPERATIONS.md).
- **Costs.** `model_prices` maps a model id to `{input, output}` per million tokens, in
  `currency`. An unpriced model shows an em dash, never `$0.00`. Check the shipped
  prices against your provider before trusting them.
- **`store_transcripts`** (false). Keeps each investigation's full message history
  (capped at 512 KB, oldest turns dropped). Needed for `heim replay`.
- **`investigator_models`** ([]). The models the investigator may run on: offered next
  to every Investigate button (that run only), on `/agents/investigator` (the default
  for every run, from the next one on) and to `heim investigate --model`. A plain id
  means an Anthropic model; other providers take the `analyst_models` form
  (`{provider: openrouter, model: …}`). `--model` accepts a full key
  (`provider|model`) or an id only one entry has. List only priced models. Empty means
  no select, a read-only panel, and the investigator's own model.
- **`analyst_models`** ([]). The models the dashboard may put in the daily analyst's
  chain on `/agents/daily`, each `{provider, model}` (plus `base_url` /
  `api_key_env` for `openai_compat`). The chosen order applies from the next run and
  stays until Reset to default. Empty means the chain is shown read-only. An override
  naming a model later removed from this list is ignored, and the YAML chain runs.
- **`instance_host_map`.** Prometheus `instance` address prefixes to host names, first
  match wins, so put longer prefixes first. The poller compares as strings: `…2` is a
  prefix of `…210` and `…241`, so the hypervisor's address goes last. An entry whose
  address is empty (an unset optional variable) is dropped.
- **`host_color_order`.** Badge colours go by position in this list. Append new hosts;
  inserting one repaints every host after it.
- **Threshold watch.** `threshold_detection` (true), `threshold_severity` (`crit`, or
  `warn` for both), `threshold_consecutive` (2 polls over the bound before an incident
  opens; streaks survive a restart).
- **`uptime_kuma.url`** (`${HEIM_UPTIME_KUMA_URL:-}`; empty turns it off).

## `config/hosts/<name>.yaml`

One file per host.

| Field | Meaning |
|---|---|
| `role` | `guest` (investigated directly), `hypervisor` (investigated through guests and its API), `ha-guest` (API only). Selects the investigation brief. |
| `investigable` | `all`, or a category list such as `[cpu, memory, temperature, disk, diskHealth, availability]`. Only these findings propose investigations. |
| `ssh` | host, port, user, key for a guest with a shell. Without it the guest is watched through Prometheus and the Proxmox API, and the brief and approval prompt drop their SSH wording. |
| `api` | base URL and `verify_ssl` for the hypervisor and Home Assistant |
| `vmid` | Proxmox VM id, display only |
| `facts` | injected into the investigator's `[FACTS]` block: topology the agent must know |
| `privileges` | injected into `[PRIVILEGES]`: must match the host's real sudoers and groups |

Adding a host: create the file, grant the read-only permission set if it has a shell
([INSTALL.md](INSTALL.md#2-read-only-access-for-the-agents)), add its address to
`instance_host_map`, and append it to `host_color_order`. For a Proxmox guest the host
name must equal the PVE guest name, or its `node_*` and `pve_*` series land on two
hosts. `config/hosts/heim.yaml` is the worked example.

## `config/tools/<name>.yaml`

`name`, the LLM-facing `description`, a JSON-schema `args` and `required`, `options`
(host binding, clip size) and `module: heim.tools.<module>:<Class>`. The class
implements `async def run(self, args) -> str` (see
[`src/heim/tools/base.py`](../src/heim/tools/base.py)). Give every new tool a guard or a
hard-scoped client, then list it in an agent's YAML. The tools are described in
[AGENTS-AND-TOOLS.md](AGENTS-AND-TOOLS.md#tools-and-guards).

## `config/agents/*.yaml`

- `investigator.yaml`: Anthropic model, `max_tokens`, `soft_step_budget` (told to the
  model, 15), `hard_step_cap` (enforced by the loop, 25), prompt template, tool list.
- `security_auditor.yaml`: the same fields, with a cap of 6 and no SSH tool.
- `daily_analyst.yaml` (`kind: analyst`): an ordered `chain` of models tried until one
  answers with parseable JSON — one completion, no tools, strict-JSON prompt. Providers:
  `anthropic`, `openrouter` (`OPENROUTER_API_KEY`), and `openai_compat` for any other
  OpenAI-compatible server such as a local llama.cpp (`base_url`, and `api_key_env`
  only if it needs a key). An entry may also set `timeout_s` (default 180) and
  `extra_body` (extra request fields). An `openai_compat` entry whose `base_url` is
  empty is dropped, so the shipped last entry, llama-server in CT 111
  (`HEIM_LLAMACPP_URL`, key in `HEIM_LLAMACPP_KEY`, 30 min timeout, Qwen3 thinking
  off), is off until the URL is set. The older `primary` / `fallback` form still loads.

Prompts live in `config/prompts/`: `analyst.md`, `investigator.md.j2`,
`security_auditor.md.j2`, and per-role briefs in `briefs/`.

## `config/queries/daily.yaml`

The 50-query catalog: `qid`, category, label, unit, direction, `warn`/`crit` bounds and
verbatim PromQL, plus the 3-day / 3 h window. Both the daily analysis and threshold
watch read it. The `qid` is part of every fingerprint, so keep qids stable and equal to
the `qid` label of any alert rule that watches the same signal.

## `config/security/checks.yaml`

The weekly audit's whole read surface: the sources (PVE GET paths, HA paths, PromQL,
fixed SSH lines) and the 47 checks with severity, parameters and recommendation. The
loader rejects any SSH line the command guard would block, any HA path outside the HA
allowlist and any PVE path outside the audit's GET allowlist. After the first run, list
accepted ports in `HEIM_AUDIT_EXPECTED_PORTS` (`:22` is built in; unset flags every
listener) and expected failed units under `expected_failed`, or mark rows false positive
on the Security page. A malformed port list fails at daemon start and in `heim check`.
