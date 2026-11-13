# Operations

## The CLI

In Docker, prefix each command with `docker compose run --rm heim`.

| Command | Does |
|---|---|
| `heim check` | validates config, the query and audit catalogues, and connectivity, item by item (Prometheus, Loki, Home Assistant, Uptime Kuma, Telegram, API keys, SMTP credentials, SSH keys) |
| `heim daemon` | the real thing: schedules, poller, approval listener, job queue, nightly backup |
| `heim dashboard [--host H] [--port P]` | the web UI (default `0.0.0.0:8300`) |
| `heim daily [--dry-run]` | one daily analysis |
| `heim poll [--dry-run]` | one poll cycle: alerts, thresholds, Uptime Kuma |
| `heim thresholds [--all]` | each catalog series' value, flag and streak |
| `heim investigate --host H [--finding TEXT] [--role R] [--metric M] [--severity S] [--model M] [--no-approval] [--dry-run]` | one investigation, run directly |
| `heim investigate --fingerprint FP` | the same, taking host and finding from an incident |
| `heim incidents [--all]` | the incident store |
| `heim incidents mute FP [--days N] [--reason TEXT]` / `unmute FP` | suppress a fingerprint (0 days = forever) |
| `heim investigations [--limit N] [--show ID]` | tracked investigations, or one with its steps and report |
| `heim jobs [--limit N] [--status S]` | the investigation job queue |
| `heim replay ID [--model M] [--prompt-file F]` | offline replay of a stored investigation |
| `heim security-audit [--dry-run] [--no-llm]` | one security audit |
| `heim log-digest [--dry-run]` | one Loki error digest (the daemon sends it daily at `schedules.log_digest`) |

`--dry-run` keeps side effects local: emails become HTML files in `out/`, Telegram, Loki
and HA sends become log lines, and approvals are granted automatically. The live
deployment is a real homelab, so prefer it for testing.

Only the daemon writes heartbeats and pings the dead-man's switch, so CLI runs never
make a stopped daemon look healthy.

## The job queue

Investigations requested from the dashboard, and re-runs, go into the `jobs` table:
queued, running, then done, failed or interrupted. The daemon claims one job at a time
every 4 seconds and runs it through the normal investigation path (approval, the
concurrency cap, delivery). Scheduled dispatch from the poller and the daily run does not
use the queue.

On start, the daemon marks investigations that were running as failed (their agent
loop died with the process) and their jobs as interrupted. They are not resumed. Pending
approvals are left alone and re-armed. A job whose investigation was parked waiting for
approval is still marked interrupted, while the investigation itself goes on; the
investigation row is the one to trust.

## Dead-man's switch

Set `HEIM_DEADMAN_URL` to a healthchecks.io-style URL. The daemon GETs it after every
completed poll cycle, including cycles that found nothing, so silence means HEIM is down.
A failed ping is one warning line. This is the only cover for the loss of the host HEIM
runs on.

## Tooling feedback issues

Set `HEIM_GITHUB_REPO`, `HEIM_GITHUB_READ_TOKEN` and `HEIM_GITHUB_TOKEN` in `.env` (see
`docs/CONFIGURATION.md`) and restart. Suggestions are posted after each poll cycle, a few
at a time. When GitHub can't be reached (outage, DNS after a reboot) the rows wait
without using up tries. When GitHub refuses a post (bad token, missing permission) it
is one warning log line and a "Retrying" row on the tool's page; after 10 refusals the
row reads "Failed". A deleted or transferred issue is replaced by a new one. The agents
only see issue text written by the repo's owner, members and collaborators, but a
private repo is still the safer choice, because the issues describe your homelab. To turn it off, empty `HEIM_GITHUB_REPO`: suggestions are still stored and
shown on the Tools page, just not queued.

## Pausing a job for maintenance

On the dashboard's **Jobs** page, pick 1 h, 4 h or 24 h next to a job and press Pause.
Until then the daemon skips that job's work and records the skipped run as "Paused", so
it never reads as overdue. The poll cycle itself keeps running, so the dead-man's switch
keeps pinging and the external watchdog stays quiet. Telegram gets one line when the
pause starts and one when it ends (within one poll interval). A pause always ends by
itself; "Resume now" ends it early. A paused daily run or weekly audit is skipped, not
caught up. A job switched off in config reads "Off" and has no Pause control.

## Backups and retention

At 03:30 local time the daemon snapshots the store with SQLite's online backup API (safe
with the live WAL database) to `<db_path dir>/backups/heim-YYYYMMDD.sqlite3`
(`./data/backups/` with compose) and keeps the newest `backup_keep` (14; 0 = never
rotate).

Then it prunes finished history older than `retention_days` (120; 0 = keep forever):
resolved incidents, findings, runs, finished investigations with their steps, and closed
jobs (at most 30 days). Heartbeats go after 14 days. Suppressions, open or suppressed
incidents, unfinished investigations and queued or running jobs are never touched. The
backup always runs first; if it fails, the prune is skipped. Large prunes are followed by
`VACUUM`. The Backup verifier agent's heartbeat records the result.

## Replay

`heim replay` re-runs a stored investigation offline to ask whether another model, or
another prompt, would reach the same conclusion on the same evidence.

```bash
heim replay 42                                  # same model: reproducibility check
heim replay 42 --model claude-haiku-4-5         # another model, same evidence
heim replay 42 --prompt-file prompts/candidate.md.j2
```

It uses the same brief and system prompt, and serves the original run's recorded tool
results back to the model. Nothing is measured live: no SSH, Prometheus, HA or Proxmox,
no approval, no email, Telegram, HA or Loki. Only the LLM is called. Each call is matched
against the recording:

- **exact**: same tool and arguments, the original result;
- **fuzzy**: same tool, other arguments, the oldest unused result for that tool
  (plausible but not an answer to that call; read the diff with more care);
- **missed**: nothing left for that tool, so the model gets an explicit "no recorded
  result" stub. Replay never invents output.

The investigation needs a stored transcript (`store_transcripts: true` when it ran). The
replay is stored as an investigation with `trigger: replay`, linked to its original, and
the CLI prints both runs' model, status, steps, tokens and cost, the hit counts and a diff
of the two `## Root cause` sections.

## Costs

The only paid part is LLM tokens: one analyst completion per daily run (the primary can
be a free OpenRouter model), one investigator session per approved investigation, and one
short audit pass a week. With `model_prices` set, each investigation and run records its
cost, shown on the investigation pages, the findings run headers, the overview's 24 h
tile and the Costs page.

## Loki error digest

Every day at 08:00 the daemon emails the last 24 h of error lines from Loki, grouped
by host, unit or container and message, most frequent first, with the expected noise
from `config/log_digest.yaml` dropped and counted. It sends on a clean day too, so a
missing email means the job is broken. A source Loki could not answer, or one that hit
the 5,000-line read limit, marks the email "incomplete"; if every source fails, the
daemon sends one Telegram line instead. Add a pattern to `ignore` when a line is
expected; keep its `why`, because the email shows it.

## Logs and audit trail

- The daemon logs to stdout (`docker compose logs -f heim`, or the journal).
- `audit.jsonl` holds one line per executed or blocked tool call.
- With Loki configured, HEIM pushes `state`, `incident`, `finding`, `category`,
  `investigation` and `action` events under `job=homelab-ai-monitor`, read by the Grafana
  dashboards in `grafana/`.
