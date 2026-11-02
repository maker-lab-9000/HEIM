# The dashboard

A web UI over HEIM's own records, laid out as a monitoring console: a grouped rail on
the left, a top bar, panels. It reads everything in the SQLite store and writes only
action rows. The daemon stays the only process that runs pipelines.

```bash
heim dashboard                  # http://localhost:8300 (--host, --port)
docker compose up -d dashboard  # or as the compose service
```

FastAPI, Jinja and vendored htmx; system fonts, one stylesheet, no build step, no chart
library. It works without JavaScript (every action is a plain form) and on a phone (the
rail becomes a row of chips; wide tables scroll inside their card). The visual system,
tokens, lamps and components, is locked in [`design.md`](../design.md).

## Access

It is HEIM's only inbound port. Keep it on your LAN or tailnet and never expose it
publicly. `HEIM_DASHBOARD_TOKEN` in `.env` turns on HTTP basic auth (any username, the
token as password). `/healthz` and `/telemetry` are exempt; `/telemetry` serves
aggregates only (see [INSTALL.md](INSTALL.md#watching-heim-itself)). The forms carry no
CSRF token, an accepted risk for a LAN-only page behind auth.

## Layout

The rail has three groups, each item with a lamp that is lit when current:

- **Workspace**: Overview, Agents, Investigations, Incidents.
- **Infrastructure**: Hosts, Metrics, Security.
- **Insights**: Findings, Recommendations, Costs.

Agents, Investigations, Incidents and Hosts carry a count. The rail's footer shows the
daemon line (Connected, Daemon quiet or No heartbeat yet, with the time of the last
poll heartbeat) and the Appearance switch (Auto, Light, Dark; stored in a cookie).

The top bar shows the page title, the date, the host count and the time in the
configured timezone. On the Overview and Agents pages it also holds the **window
switch**, Live / 24 h / 7 d. Live shows each agent's last runs; 24 h and 7 d cut the
window into equal slots and mark a slot missed when a run was due and none came. The
switch scopes only the run strips and tool counts: what is open stays what is open now.

## The colour code

Every state belongs to one family, grouped by who has to act. The mapping lives in one
place (`dashboard/format.py`); templates never choose a colour.

- **Orange, waiting on you**: pending approval, needs you, open, queued.
- **Green, in progress or done well**: running, clearing, done, confirmed, approved,
  connected.
- **Red, broken**: critical, failed, error, interrupted, dismissed.
- **Amber, getting worse**: warning, degraded, overdue, missed, incomplete.
- **Blue-grey, settled**: resolved, complete, healthy, idle, normal.
- **Lamp off, set aside**: declined, muted, suppressed, false positive, paused, unknown.

A state always has its word next to its lamp; no glyph or emoji stands for a state.
Pressed keys follow the same code: Done, Approve and Confirm turn green; Dismiss and
Decline red; False positive grey.

## Pages

- **Overview.** Four instrument cards: infrastructure condition (critical and warning
  counts), agent coverage (how many agents are reporting), observations (time since the
  last sync with Prometheus), and what requires you. Then **Needs attention**: open
  incidents by severity, each saying what HEIM is doing about it, and runs that need a
  re-run. **Needs you**: approvals, physical checks the agent cannot make remotely, and
  manual checks. Then the **Agents** panel, and below it the health tiles (open
  incidents, running investigations, pending approvals, tokens and cost in 24 h, queue),
  the latest analysis with a per-host strip, the last daily runs, the tool-usage card
  (calls, blocked, average time and tokens per tool, agent and model, with the latest
  tooling feedback), token usage by weekday, recent investigations and recent findings.
- **Agents** (`/agents`). The seven agents with state, scope, last success and a run
  strip; a stale or failing one gets a monitoring-gap line. Each has a page
  (`/agents/<key>`) with its coverage, cadence, last error, a run table, a link to its
  evidence and, for the investigator and the security audit, its last 50 tool calls.
- **Investigations.** A filterable list (status, host, trigger). Running rows refresh
  every 5 seconds; queued jobs appear as ghost rows on top. The detail page shows the
  header (host, status, trigger, agent and model, tokens, cost, duration, fingerprint),
  what triggered it, then **Observations**: the tool-call transcript with a burn line
  showing each step's share of input tokens. After it, the report sorted into
  **Interpretation** (summary, root cause, confidence), **Proposed actions** (suggested,
  not carried out) and **Completed actions** (what the operator did: approved, declined,
  marked resolved or needing a human, muted). The full report, the brief sent to the
  agent and, when stored, the full transcript are folded below. A pending approval
  shows how long it has been waiting.
- **Incidents.** The store: severity, status and lifecycle, the dispatch lock, mute
  state, how often it was seen, linked investigations.
- **Findings.** History grouped by run, worst first, with verdict keys and links to the
  evidence: the metric row, the incident, the investigation.
- **Recommendations.** Open remediation steps from open incidents' findings and from
  complete investigation reports, each linked to its source, with Done and Dismiss.
  The same advice coming back on a later run keeps its mark.
- **Security.** The latest weekly audit by severity (new, persisting, carried, with how
  many weeks each has been reported), what was resolved since the previous audit, the
  full report and AI assessment, the auditor's feedback, and a history of past audits.
  Dry runs never appear.
- **Metrics.** The daily email's data, live: per host and category, current and average
  values, three-day trend and change, read from Prometheus through the daily pipeline
  (cached 10 minutes, with a refresh button). Each chart states its question, unit,
  window and thresholds, and shows gaps where data is missing.
- **Costs.** Tokens and cost per day over 7 d, 30 d or all.
- **Hosts.** One card per configured host: role, open incidents, last finding, last
  investigation, and Investigate now.

Lists of investigations, incidents and findings load 50 rows at a time, with a
"Load 50 more" link.

## Actions

Every action is a POST form that redirects back; with htmx only the affected panel is
replaced, with a one-line confirmation. Subjects travel as form fields, never in the
URL.

| Action | Where | What it writes |
|---|---|---|
| Investigate | host cards, incidents | a queued job (optionally with a model from `investigator_models`) |
| Re-run | investigations, Needs attention | a queued job linked to the earlier run (`retry_of`) |
| Approve / Decline | pending investigations | the approval decision the daemon is waiting on |
| Confirm / False positive | findings, security | a verdict; false positive also mutes the fingerprint |
| Mute / Unmute | incidents | a suppression and the incident's `suppressed` status |
| Done / Dismiss | recommendations | the recommendation's state |

Decisions are reversible: pressing a pressed verdict or recommendation key clears it,
the other key switches it, and leaving False positive lifts the mute it set. While a run
for a subject is in flight, its Investigate or Re-run key shows pressed and links to it
(Investigating, Awaiting approval, or the queue).

The full write surface is the allow-list `_ACTION_HELPERS` in `dashboard/app.py`.
