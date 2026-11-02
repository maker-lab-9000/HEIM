# Installing HEIM

This covers a full setup: prerequisites, the read-only access the agents need, Docker
or a bare service, and the optional sources. For the settings themselves see
[CONFIGURATION.md](CONFIGURATION.md).

## 1. Prerequisites

- **Prometheus** reachable from HEIM, scraping your hosts. HEIM's queries expect
  node_exporter, cAdvisor and the Proxmox VE exporter; smartctl_exporter feeds the
  disk-health rows. Alert rules must carry `severity` and `qid` labels (see "Alert
  rules" below).
- **An Anthropic API key.** Everything else is optional.
- Python 3.11+ for a bare install, or Docker with compose v2.

Run HEIM on a guest of its own (on Proxmox, a small VM with Docker; Docker inside LXC
needs `nesting=1` and breaks on upgrades). A separate guest keeps HEIM alive, and
alerting, when the main server goes down. HEIM cannot report the loss of the box it
runs on: set up the dead-man's switch ([OPERATIONS.md](OPERATIONS.md)) for that.

## 2. Read-only access for the agents

The investigator runs model-written commands, so the operating system and the APIs are
the real boundary. The guards in HEIM are a second layer, not the first.

- **SSH (hosts with a shell).** A dedicated user (default `monitoring-agent`, set
  `HEIM_SSH_USER`) with its own key, a scoped passwordless sudoers list of read-only
  commands (`du, df, findmnt, lsof, ls, ss, agent-docker`), membership of the
  `systemd-journal` and `adm` groups, `kernel.dmesg_restrict=0`, and a root-owned,
  read-only `agent-docker` wrapper (`ps|logs|stats|top|inspect|system df|images`, logs
  tail-bounded, inspect with env redacted). No `sudo cat` or `sudo grep`: everything the
  agent reads ends up in emails, Telegram and the LLM API, so it must not reach secrets.
  The host's `privileges:` block in `config/hosts/<name>.yaml` must describe exactly what
  you granted, because the agent plans around it.
- **Proxmox VE.** An API token for a user with the auditor role (`PROXMOX_TOKEN`, the
  full `user@pve!tokenid=secret`). The security audit uses the same token.
- **Home Assistant.** A long-lived access token from a dedicated non-admin user
  (`HA_TOKEN`). Writing the `sensor.pam_*` report entities needs an admin token
  (`HA_PUSH_TOKEN`); without it HEIM tries `HA_TOKEN`, which a non-admin user cannot
  use for writes.
- **Telegram.** A bot token (`TELEGRAM_BOT_TOKEN`) and your chat id
  (`HEIM_TELEGRAM_CHAT_ID`). One bot serves one daemon: a second daemon on the same
  token steals its updates, so use a separate bot for local testing, or `--dry-run`.
- **SMTP.** `SMTP_USER` / `SMTP_PASSWORD` (for Gmail, an app password).

## 3. Docker (recommended)

HEIM opens no inbound port except the optional dashboard. Telegram approvals use long
polling, not a webhook.

```bash
git clone <this repo> && cd heim
cp .env.example .env && $EDITOR .env
echo "HEIM_SSH_KEY_FILE=$HOME/.ssh/pam_agent" >> .env
# config/settings.yaml is optional: without it HEIM uses settings.example.yaml,
# which reads everything deployment-specific from .env. Copy it only to change
# structure (schedules, retention, which channels are on).

docker compose run --rm heim check            # config + connectivity, item by item
docker compose run --rm heim daily --dry-run  # report lands in ./data/out/
docker compose up -d --build                  # daemon + dashboard
docker compose logs -f heim
```

- `heim` is the daemon: schedules, the poller, the approval listener and the job queue.
  `dashboard` serves the web UI on `:8300`. Remove the `dashboard` service if you don't
  want it.
- State lives in `./data` (the SQLite store, `audit.jsonl`, dry-run reports, backups).
  `config/` is mounted read-only; secrets come from `.env`. The containers create
  `./data` on first start and fix its ownership, then drop to an unprivileged user.
- One-off commands run with `docker compose run --rm heim <command>`.
- The image is built on the host that runs it, so ARM and x86 need nothing special.
- Keep the dashboard on your LAN or tailnet. `HEIM_DASHBOARD_TOKEN` in `.env` turns on
  HTTP basic auth (any username, the token as password).

## 4. Bare install

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
cp .env.example .env && $EDITOR .env
.venv/bin/heim check
.venv/bin/heim daemon            # in one terminal or as a service
.venv/bin/heim dashboard         # http://localhost:8300
```

As a systemd service:

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

Add a second unit with `ExecStart=/opt/heim/.venv/bin/heim dashboard` for the web UI.

## 5. Observability stack

In this homelab, Prometheus, Loki and the alert rules are configured and deployed by a
separate repository (ansible-homelab, `stacks/ubuntu-server/prometheus/` and
`stacks/ubuntu-server/loki/`). HEIM only reads Prometheus and writes Loki. This repo
ships the Grafana dashboards; see [`grafana/README.md`](../grafana/README.md).

### Alert rules

The alert poller turns firing rules into incidents. Its contract with the rules:

- every rule carries `severity` and `qid` labels. Where a rule watches the same signal
  as a query in [`config/queries/daily.yaml`](../config/queries/daily.yaml), it reuses
  that qid, so the poller and the daily analysis build the same fingerprint;
- a qid HEIM has never seen needs a category and naming rule in
  `src/heim/incidents/poller_logic.py`, or the poller files it under `other`;
- physical disks are named by role, never by kernel name: a `homelab:disk_role:info`
  recording rule maps each disk's serial to a role, and per-disk rules carry it as a
  `disk` label. HEIM's disk queries join the same rule, so without it the daily report
  has no SMART, SSD-wear or CRC rows.

Check `/api/v1/rules` on Prometheus before trusting that a rule is live.

### Loki

Set `loki.url` to enable both the investigator's `loki_query` tool and HEIM's event
stream (`job=homelab-ai-monitor`). The Grafana dashboard
`grafana/dashboards/homelab-ai-operations.json` reads that stream. Without Loki the
tool answers "not configured" and the events are skipped.

### Uptime Kuma

Set `HEIM_UPTIME_KUMA_URL` and `UPTIME_KUMA` (an API key from Settings → API Keys) in
`.env`. HEIM reads `/metrics` with basic auth and an empty username. No `settings.yaml`
change is needed; `uptime_kuma.url: ""` there turns the source off. `heim check` prints
the monitor count and every monitor that maps to no HEIM host. Behaviour is described in
[AGENTS-AND-TOOLS.md](AGENTS-AND-TOOLS.md#uptime-monitor).

### Watching HEIM itself

The dashboard serves `/telemetry` in Prometheus text format, without auth (aggregates
only). Scrape it:

```yaml
- job_name: 'heim'
  metrics_path: /telemetry
  static_configs:
    - targets: ['<heim-host>:8300']
```

It exposes `heim_open_incidents`, `heim_suppressions_active`, `heim_jobs_queued`,
`heim_investigations_total{status=…}`, `heim_tokens_in_total`, `heim_tokens_out_total`,
`heim_cost_total` and `heim_last_daily_run_age_seconds` (absent until the first daily
run). All are gauges: retention can lower even the totals.

## 6. Example layout

This homelab runs HEIM on its own Proxmox guest, `heim`, which holds only the SQLite
store, Docker and the nightly backup. `ubuntu-server` runs Prometheus, Loki and the
watched workloads. `homelab` is the hypervisor (node_exporter, smartctl_exporter, the PVE
exporter). `home-assistant` is watched through its API and Prometheus integration.
`heim` itself has no SSH access; it is monitored through node_exporter and the Proxmox
API, and the prompts tell the agents to judge its near-idle disk and network in absolute
bytes.
