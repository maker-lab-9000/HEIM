# Uptime Kuma as an alert source — design

Date: 2026-11-01 · Status: draft, awaiting operator approval

## Intent

Uptime Kuma, which runs on the home-assistant VM, watches about 45 services across the homelab: web UIs, exporters, SSH and Samba ports, pings and the k8s nodes. In the operator's words, every monitor that isn't paused is expected to be up, so any downtime is unexpected and worth investigating.

Today HEIM learns about an outage only indirectly, through a Prometheus alert or a trend in the daily report. A stopped container such as n8n can go unnoticed until someone tries to use it.

HEIM should treat a monitor going down as an incident:

- tell the operator on Telegram which service is down, on which host;
- offer an approval-gated investigation that finds out why.

## Goals (decided with the operator)

1. HEIM polls Uptime Kuma on its existing 5-minute poll cycle.
2. Each monitor is mapped to the VM it runs on.
3. When a monitor goes down, one Telegram message names the service and its host and carries Approve and Decline buttons for an investigation. This is the existing durable approval flow, and approval stays required.
4. An approved investigation runs the existing investigator. The agent works out which process or container on that VM serves the monitored target, and why it stopped.
5. The k8s nodes are report-only: the same message without buttons, and no investigation for now.
6. If HEIM can't reach Uptime Kuma, that is an alert of its own, never silence.
7. On recovery, a short "back up after N min" message is sent and the incident closes itself.
8. Outages appear on the dashboard's incidents page like any other incident. There is no separate Uptime Kuma page.

## Non-goals

- Investigating the k8s nodes. HEIM has no SSH access to them and Prometheus doesn't scrape them; this is left for later.
- A dashboard page or widget for Uptime Kuma.
- Changing anything in Uptime Kuma. The API key only reads `/metrics`.
- Removing the single point of failure where Uptime Kuma lives on the home-assistant VM. Accepted for now.
- Routing Uptime Kuma through Prometheus (see "Source").

## Anti-goals (a failure even if it technically works)

- **A storm.** One VM going down must not produce one message and one approval prompt per monitor.
- **Silence, or false recovery, when Uptime Kuma is unreachable.** No data is not "up": HEIM must never resolve an outage because a poll failed.
- **Flapping.** A bouncing service must not produce a stream of down and up messages (see "Flapping" under Incidents).
- **The wrong VM.** A monitor must never be attributed to the wrong host. For example, an address-prefix match must not put a k8s node on the Proxmox host.
- **Deployment identity in git.** The Uptime Kuma URL, any address and the API key stay in `.env`, because the HEIM repo is public.
- **The dashboard acting.** The daemon polls. The dashboard only shows the resulting incidents and stays a non-executor.

## What Uptime Kuma provides (recon, 2026-11-01)

- **Version and auth.** Version 2.5.8. The API key in `.env` (`UPTIME_KUMA`) authenticates `GET /metrics` with HTTP basic auth: empty username, the key as password. Bearer auth is rejected with 401. The key is read-only.
- **The `/metrics` export.** It uses Prometheus text format and has one `monitor_status` gauge per **active** monitor, with labels `monitor_id`, `monitor_name`, `monitor_type`, `monitor_url`, `monitor_hostname` and `monitor_port`. Values: `0` down, `1` up, `2` pending (Uptime Kuma is retrying), `3` maintenance. There are also response-time and certificate-expiry gauges.
- **Paused monitors.** They are absent from `/metrics`, so "except what's paused" needs no handling.
- **No error message or down-since time.** `/metrics` carries neither; they are only available through Uptime Kuma's Socket.IO API, which needs a username and password. HEIM's message therefore says when HEIM first saw the outage, and the agent finds the reason.
- **Monitor types in use.** `http`, `keyword`, `port` and `ping`.
  - For `http` and `keyword`, the target is `monitor_url`.
  - For `port` and `ping`, `monitor_url` is empty or a bare scheme, and the target is `monitor_hostname` (plus `monitor_port`).
- **Addresses.** Every monitor but one targets a literal IP. The exception targets a Tailscale hostname whose first label is a HEIM host name (`ubuntu-server.<tailnet>.ts.net`).
  - The addresses are the four HEIM hosts: ubuntu-server, homelab, home-assistant (Home Assistant itself and Grafana) and heim.
  - The three k8s nodes are not HEIM hosts.

## Decided behaviour

### Source and configuration

- **Where polling runs.** The daemon polls Uptime Kuma directly, as a **third independent half** of the poll cycle, next to the alert and threshold halves in `pipelines/poller.py`. A failure in any half never aborts the others. The threshold half (`pipelines/thresholds.py` plus `_run_thresholds`) is the model: pure decision logic, with I/O at the edge.
- **Configuration.** `settings.uptime_kuma.url: "${HEIM_UPTIME_KUMA_URL:-}"`, where empty means the source is disabled. The API key comes from the environment variable `UPTIME_KUMA`. Both go into `.env.example`, and the URL setting into `config/settings.example.yaml`.
- **Direct, not through Prometheus.** *My call, stated to the operator:* it keeps the change in one repo, it doesn't depend on Prometheus, and Uptime Kuma already retries a check before it reports down.

### Which host a monitor belongs to

1. **The target address.** The host part of `monitor_url` when it has one, otherwise `monitor_hostname`.
2. **A literal IP** maps to the HEIM host whose `instance_host_map` key **equals** that IP. Do not use the existing `startswith` prefix match: it would map the address of a k8s node to the Proxmox host whenever the Proxmox host's address is a string prefix of it, which is the case in this deployment.
3. **A hostname** maps to the HEIM host whose name equals its first DNS label, case-insensitively.
4. **Unmapped.** Anything else is report-only. Its incident host is the bare target address, so its monitors still group together, and the message calls it "not a HEIM host". Today this covers the k8s nodes.

"The agents figure out what service runs on which VM": the VM is the mechanical part above. The agent's part is the process or container behind the target on that VM.

### Incidents

- **Fingerprint and ownership.** The fingerprint is `<host>|uptime_down|<monitor name>`. Descriptions carry an `[uptime] ` prefix, a fourth ownership marker next to `[alert] `, `[metric] ` and plain LLM text. This path opens and resolves only `[uptime] ` rows (AGENTS.md invariant 3, applied to this path).
- **Opening.** An incident opens on the **first poll that sees status 0**. *My call:* Uptime Kuma has already debounced the check with its own retries, and waiting a further 5 minutes would only delay a 3am message.
- **Pending and maintenance.** Status `2` and `3` neither open nor resolve anything. They count as "no change", so they don't advance a resolve either.
- **Recovery.** An incident resolves after **2 consecutive polls that see status 1**, the same `RESOLVE_AFTER` rule as the other paths.
- **Flapping (decided with the operator).**
  - If a monitor goes down again **within an hour of its last recovery**, HEIM reopens the same incident quietly. It sends no new prompt and no "down" message, and recoveries while it flaps send no "back up" message.
  - Instead, at most **one line per hour per monitor**, for example "n8n keeps flapping (3 outages in the last hour)".
  - Once the monitor has stayed up for a full hour, it counts as stable. One closing line follows, for example "✅ n8n stable again after 3 outages" *(my call)*, and the next outage is treated as new.
  - The flap state must survive a daemon restart.
- **Paused or deleted monitors.** A monitor that disappears from `/metrics` while its incident is open (paused or deleted) resolves after **2 consecutive successful polls** without it, with a one-line note instead of a recovery message. *My call:* by the operator's rule a paused monitor is expected not to run. The second poll matters because Uptime Kuma starts its monitors one by one after a restart, so one poll right after a restart can list only some of them.
- **Severity.** Every uptime incident is **critical**: a service the operator expects to run is down.
- **Mutes.** Muted fingerprints (`suppressions`) are skipped, through the same filters the other halves use, so a monitor can be muted from the dashboard.
- **Renames.** A renamed monitor gets a new fingerprint: the old incident resolves when its name disappears from `/metrics`, and the new name opens fresh.
- **The daily run leaves `[uptime]` incidents alone.** The daily pipeline filters them out of the open incidents it passes to `reconcile()`, the same way the suppression filters work, so a daily run can neither miss-count them nor resolve them. *My call.* Without the filter, a daily run would close an outage that Uptime Kuma couldn't report on for a day, or supply the second "up" count. As a consequence they don't appear in the daily email's incident summary: Telegram and the dashboard are where they show. `[alert]` and `[metric]` incidents have the same exposure when Prometheus is down for a day; that is out of scope here.

### Telegram

- **One message per host.** On each poll, newly opened `[uptime]` incidents are grouped **by host**, giving one message per host, never one per monitor.
- **Investigable hosts.** For these, that message *is* the approval prompt, for example:

  > 🔴 Down on ubuntu-server: n8n (http …:5678), Bitwarden (http …:8080), first seen 03:02. Approve to investigate?

  It uses the existing durable flow (`inv:<id>` buttons, store-backed, no timeout by default) and starts **one investigation per host group**, with the down monitors as its findings.
- **Which hosts are investigable.** The rule HEIM already uses:
  - SSH hosts (ubuntu-server);
  - the Home Assistant host (home-assistant, which also runs Grafana);
  - the hypervisor (homelab), for the new `availability` category, which is added to `investigable` in `config/hosts/homelab.yaml`. That keeps hypervisor gating as data.
- **Report-only hosts.** The k8s nodes, any unmapped address, and heim get the same message without buttons, through `rt.notify`. *My call for heim:* it is an API-only guest, and HEIM never auto-investigates those elsewhere. An outage of heim itself mostly means HEIM is down too.
- **More downs on the same host.** If a host already has an uptime investigation **waiting for approval**, newly down monitors on it **join that investigation** instead of getting a second prompt. *My call: an outage typically grows over a few polls as Uptime Kuma's retries run out, and the agent should hear about all of it.*
  - The investigation's stored findings and brief are updated, so an approval re-armed after a restart includes the new monitors.
  - The new incidents join the group's dispatch lock.
  - The operator gets a plain message: "also down on <host>: …, added to the pending investigation".
  - If that host's investigation is already running or finished, the new monitors form a new group with its own prompt.
- **Recovery messages.** Recoveries are grouped per host and per poll, for example "✅ Back up on ubuntu-server: n8n (down 14 min)". An approval still waiting is left as it is: approving after recovery still answers "why did it go down?". The agent must know the service has recovered by the time it runs; how it learns that is up to the builder.
- **Decline.** The poll never re-proposes a declined or ignored investigation, matching `[alert]` incidents. The operator can queue one from the dashboard.
- **Dispatch lock (invariant 2), applied to groups.** Queuing a group investigation sets `investigated=true` on **every** incident in the group. Decline, needs-human and timeout reset it on every one of them.

### Uptime Kuma unreachable

- **What counts as a failed poll.** An HTTP error, a timeout, a non-200 response, or a body with no `monitor_status` samples.
- **No writes.** A failed poll writes nothing for monitors and resolves nothing.
- **Alerting.** After **2 consecutive failed polls**, HEIM opens one report-only incident on the host that Uptime Kuma's own URL maps to (home-assistant today), with the message:

  > ⚠️ Can't reach Uptime Kuma: service outages are not being watched.

  The first successful poll resolves it, with a short "watching again" message. The failure count must survive a daemon restart. *My call:* two polls, so one transient failure doesn't page.

### The investigation

- **Plumbing.** It reuses `dispatch_all` and `run_investigation`, with a new trigger value, `uptime`, so the dashboard can tell these runs apart.
- **Findings.** For each down monitor: its name, type, target (URL, or host and port), the time HEIM first saw it down, and the fact that it comes from Uptime Kuma.
- **What the brief asks.** Find which container or process serves that target on the host, whether it is running, its recent logs (SSH `docker logs` or `journalctl`, `loki_query`, or Home Assistant add-on logs), and the likely cause. On the hypervisor, use the Proxmox journal (`/nodes/homelab/journal`, already allowed) and Prometheus. *My call:* the investigator's Proxmox guard is **not** widened to `/nodes/homelab/services` (invariant 4; the security audit's separate allowlist is not the agent's).
- **Builder's choice.** A new brief template, or findings text on top of the existing role briefs.

### Visibility and operations

- **Dashboard.** The incidents page shows `[uptime] ` incidents like any other; nothing new is required.
- **Loki.** `incident` events carry category `availability`. Event types are unchanged and the category value is low-cardinality (invariant 5).
- **`heim check`.** Reports whether Uptime Kuma is reachable, whether the key is accepted, the number of active monitors, and any monitors that map to no HEIM host.
- **`heim poll --dry-run`.** Evaluates the uptime half and prints what it would do. For this half it writes **nothing** to the store: no incidents and no failure counter. *My call:* the CLI shares the daemon's SQLite file, and a row written without its message would make the daemon treat the outage as already announced.
- **Poll summary.** Gains `uptime_*` counters. Those that mean "something happened" join `_RECORDABLE`.

## Constraints

- **AGENTS.md invariants:**
  - deterministic fingerprints, never LLM wording;
  - the dispatch lock (including for groups, see above);
  - per-path ownership;
  - a read-only agent;
  - Loki schema compatibility;
  - no deployment identity in git.
- **Pure logic, tested.** The decision logic (monitor to host, open, resolve, group, unreachable) is pure, without I/O, and unit-tested. The HTTP fetch and parsing sit at the edge.
- **Side channels.** Telegram and Loki failures are logged and swallowed. An exception in the uptime half never reaches the alert and threshold halves.
- **Tests.** The existing suite stays green.

## Left to the builder

- Module and function names, and file layout.
- How the API key is read.
- `/metrics` parsing.
- Any store changes needed for the unreachable counter and the group lock.
- Message wording beyond the content specified above.
- Brief wording.
- How a recovered state reaches an investigation that runs after recovery.
- Tests beyond the behaviours listed here.
