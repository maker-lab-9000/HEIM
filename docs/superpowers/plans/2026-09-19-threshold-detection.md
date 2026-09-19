# Threshold detection + metrics header detail

**Goal:** A metric that crosses its configured `crit` threshold must be able to open an incident and dispatch an investigation on its own — today only Prometheus alert rules (fast path) and the LLM's daily findings can. Plus: the metrics page header must name *which* host and resource is crit, not just count them.

**Spec:** this document. Design system: `docs/design/dashboard-ui.md` §1–4.

## Context: why this is needed

`/metrics` computes `ok|warn|crit|na` flags from the thresholds in `config/queries/daily.yaml`, but those flags are **presentational only**. Nothing keys off them. The two paths that can open an incident are:

- `pipelines/poller.py` — polls `/api/v1/alerts`, i.e. only rules written in `prometheus/alerts.yml`;
- `pipelines/daily.py` — the twice-daily LLM run, and only for findings the model chooses to raise.

So a metric can sit at crit on the dashboard indefinitely with no incident and no investigation. Observed live: `pve_vm_cpu` on `qemu/100` read 102.5% against `crit: 95` and nothing happened.

## Observed data that shapes the design (do not skip)

Querying `pve_cpu_usage_ratio{id=~"qemu/.*"} * 100` over 2 hours at 5-minute step: `qemu/100` had **1 of 24 points above 95** — the current one. The crit is a single-scrape spike, while the 3-day daily averages (8.6 → 12.5 → 20.9) show a real but far-from-critical climb.

Dispatching an investigation on the first crit sample would therefore have burned an agent run and a Telegram approval on a blip. **Hysteresis is not optional.**

## Part A — threshold detection

### A1. Config (`src/heim/config.py` + BOTH settings yamls, kept byte-identical)

```yaml
# Open incidents from metric thresholds (config/queries/daily.yaml warn/crit),
# not just from prometheus/alerts.yml rules. Evaluated on the poller's cadence.
threshold_detection: true
threshold_severity: crit        # crit | warn  (warn also includes crit)
threshold_consecutive: 2        # consecutive polls above threshold before opening
```

### A2. Evaluation (new `src/heim/pipelines/thresholds.py`)

- Fetch: one **instant** query per catalog entry (`/api/v1/query`), concurrently, `neverError` per query like the daily path. ~49 instant queries per poll is trivial for Prometheus; do NOT reuse the 3-day range fetch.
- Flagging and identity **must reuse the daily path's logic** — import `_flag_for`, `_host_from_metric`, `_series_name` from `heim.metrics.aggregate` (do not reimplement; if that means promoting them to public names, do that rename in aggregate.py and update its callers).
- Fingerprint: `host|qid|name` — byte-identical to the daily reconcile and the alert poller, so the same underlying problem is ONE incident no matter which path sees it first.
- Pure function `decide(samples, open_rows, streaks, now_iso, routing, cfg) -> ThresholdDecision` returning rows to upsert, dispatches, notifications, Loki events, and the streak updates. No I/O in it.

### A3. Hysteresis and ownership

- A fingerprint must be at/over threshold on `threshold_consecutive` **consecutive** polls before an incident opens. Streaks persist across daemon restarts: new store table `threshold_streaks(fingerprint TEXT PRIMARY KEY, count INTEGER, severity TEXT, last_seen TEXT)`. A poll where the series is back under threshold clears its streak row.
- Description prefix `[metric] ` — a third ownership marker alongside `[alert] ` and the LLM's plain text. **This path resolves only `[metric] `-prefixed incidents**, after 2 consecutive under-threshold polls, exactly mirroring the alert poller's rule.
- If an incident for that fingerprint already exists from another path, do NOT duplicate it and do NOT re-dispatch: update `lastSeen`/`timesSeen` only. Escalation (warn→crit) follows the existing rule.
- Suppressed fingerprints are skipped — reuse `pipelines/suppression.py`'s filters, which already gate the other two paths.

### A4. Wiring (`src/heim/pipelines/poller.py`, `src/heim/daemon.py`)

Run the threshold evaluation inside the existing 5-minute poll, after the alert diff, sharing its store writes, Loki emits, notification path and `dispatch_all` (so the approval gate, the concurrency cap and suppression all apply unchanged). If `threshold_detection` is false, skip entirely. A failure in the threshold half must not abort the alert half, or vice versa.

### A5. CLI

`heim poll` output gains the threshold counters. Add `heim thresholds` printing each catalog entry's current value, flag and streak — the operator's way to see what is about to open.

## Part B — metrics header names the offenders

`/metrics`'s header card currently reads `× critical | 1 crit · 4 warn · 0 no-data | 3-day window · as of 10:16 (cached 4m)` — it says how many, never which.

Add, directly under that line and only when there is at least one crit/warn series, a compact table of the offenders (worst first, crit before warn, then by |Δ| desc; cap at 8 rows with a `+N more` line linking to the filtered view):

| col | render |
|---|---|
| status | the existing flag pill |
| host | `m.hostbadge()` |
| resource | the metric label, plus its device/mount/id in mono `--ink-2` when present |
| current | mono, humanized |
| Δ | the existing arrow + percentage treatment |

Reuse the metrics tables' existing column classes and pills; **add no new CSS rules** (the file is at 20,971 B against a 20,992 B cap) — if that proves impossible, raise the cap by the true minimum with a one-line comment and say so in the report.

## Tests

- `decide()`: below-threshold → nothing; first crit poll → streak 1, no incident; second → incident opens with `[metric] ` prefix + dispatch; a poll under threshold clears the streak so a later crit starts from 1 again (this is the 102.5%-spike case — pin it with the real numbers from the observation above); 2 clear polls resolve a `[metric] ` incident; an `[alert] `-prefixed or LLM-born incident for the same fingerprint is NOT resolved by this path and NOT duplicated; suppressed fingerprints skipped; `threshold_severity: warn` includes crit.
- Fingerprint parity: assert a threshold-detected `pve_vm_cpu` on `qemu/100` produces exactly the fingerprint the daily reconcile produces for the same series (build both and compare — this is the test that stops the two paths double-investigating).
- Store: streak upsert/clear/persistence.
- Header table: renders the crit row naming host + resource; absent when everything is ok; the `+N more` path.
