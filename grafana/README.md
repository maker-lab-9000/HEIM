# AI Observability — Grafana + Loki

A self-hosted **Homelab AI Operations** dashboard that surfaces the AI monitor's analysis,
root-cause investigations, incidents, and risk — the AI layer of the monitor, alongside the
raw infra metrics you already have in Prometheus.

## Architecture

Two datasources feed one dashboard:

- **Prometheus** (existing) — all raw-infra + quantitative disk panels (filesystem %,
  root-FS-over-time, top growing mounts, forecast via `predict_linear`, days-until-full).
- **Loki** (new) — the AI event stream. n8n pushes one structured JSON log line per finding,
  incident state, investigation result, agent action, and run snapshot. Everything AI/agent on
  the dashboard is LogQL over these events.

```
 Prometheus ──► Grafana ◄── Loki
                  ▲           ▲
   (raw metrics)  │           │ POST /loki/api/v1/push
                  │     n8n sub-workflows:
                  │       • PAM 50 Emit: Loki event push      (9yL6uQIWSPl8lv0D)
                  │       • PAM 51 Emit: State snapshot       (DY91sremUJ6kz7v0)
```

## 1. Deploy Loki (on the ubuntu-server VM, data on `/docker-data`)

```bash
sudo install -d -o 10001 -g 10001 /docker-data/loki   # Loki runs as uid 10001
cd loki && docker compose up -d
curl -s http://localhost:3100/ready                    # -> ready
```

Loki listens on `:3100`, published on all interfaces so both n8n (same VM, outside Loki's
docker network) and Grafana (different VM) can reach it at `http://YOUR_SERVER_IP:3100`.
Config: single-binary, filesystem storage, **90-day retention** (`loki/loki-config.yml`).

> **Auth:** `auth_enabled: false` + published port = readable/writable by anyone on the
> LAN/tailnet. For a homelab this is usually fine; to lock it down, firewall `:3100` to the
> n8n + Grafana hosts, bind it to the tailnet interface, or front it with a basic-auth proxy
> (then add an `httpHeaderAuth` credential to the *PAM 50 Emit: Loki event push* HTTP node).

## 2. n8n → Loki

The push URL is set on the *PAM 50 Emit: Loki event push* HTTP node as
`{{ $env.LOKI_URL || 'http://YOUR_SERVER_IP:3100' }}/loki/api/v1/push`. Set `LOKI_URL` in
the n8n container's env to keep the IP out of exported workflow JSON. No credential is needed
while Loki is unauthenticated.

Both emit sub-workflows must stay **active** (instance rule: active callers require active
sub-workflow targets).

## 3. Add the Loki datasource in Grafana (HA VM)

Either drop `grafana/provisioning/datasources/loki.yml` into Grafana's provisioning dir and
restart, or add it via UI (**Connections → Data sources → Add → Loki**, URL
`http://YOUR_SERVER_IP:3100`). Save & test. Datasource uid: `homelab_loki`.

## 4. Import the dashboard

**Dashboards → New → Import → Upload JSON**, pick
`grafana/dashboards/homelab-ai-operations.json`, and map the two inputs:
`DS_PROMETHEUS` → your Prometheus, `DS_LOKI` → the Loki above.

Prometheus panels + the state tiles/donut/incident-table populate immediately (from events
already pushed). The **Incident Timeline** fills on the next monitoring run (it reads the
`sevScore` field on `incident` events); the **Latest Investigation Summary / Last Actions /
Recommended Actions** panels fill on the next investigation.

## Loki event model

| `event` | Emitted from | Key labels | Key fields |
|---|---|---|---|
| `state` | main run + approval/investigation transitions | `job`, `event` | `healthScore`, `activeIncidents`, `pendingApproval`, `riskByCategory.*`, `lastRunMs`, `agentOk` |
| `incident` | main run, per current incident | `host`, `severity`, `status`, `category` | `fingerprint`, `finding`, `confidence`, `sevScore`, `detectedAt` |
| `investigation` | investigation completes | `host`, `status` | `rootCause`, `confidence`, `impact`, `recommendedActions`, `tokenEstimate`, `nSteps` |
| `action` | each agent phase | `host`, `phase` | `fingerprint`, `message`, `ts` |

**LogQL gotcha (baked into the dashboard):** `| json` promotes *every* field to a stream
label, so events with different values become different streams and `last_over_time` returns
one value per stream. The stat/donut queries therefore extract a single field
(`| json v="activeIncidents" | unwrap v`) so all events collapse to one `{job,event}` stream and
`last_over_time` returns the genuine latest value.

## Files

- `loki/docker-compose.yml`, `loki/loki-config.yml` — Loki service (deploy on ubuntu-server).
- `grafana/provisioning/datasources/loki.yml` — Grafana Loki datasource.
- `grafana/dashboards/homelab-ai-operations.json` — the dashboard model.
- `grafana/dashboards/loki-alerts-findings.json` — standalone **Alerts & Findings** dashboard (Loki-only): incident stream + severity trends, fast-path `[alert]`-born incidents, LLM findings/recommendations, category status, **AI investigation reports** (root cause + remediation from `investigation` events, agent phase timeline), raw event logs. Import the same way; map only `DS_LOKI`.
