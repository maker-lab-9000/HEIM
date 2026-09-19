# Threshold detection + metrics header detail — implementation report

Branch `feat/threshold-detection`, worktree `.claude/worktrees/dashboard-leftovers`.
Spec: `docs/superpowers/plans/2026-09-19-threshold-detection.md`.

## Verification command

```
.venv/bin/pytest -q
724 passed, 12 warnings in 19.22s
```

Baseline was 697; +27 new tests (23 in `tests/test_thresholds.py`, 4 in
`tests/test_metrics_page.py`). No test was deleted or weakened; two were
re-scoped (see "Judgment calls").

---

## Implementation, file by file

### `src/heim/metrics/aggregate.py` — helper promotion (A2)
- `_flag_for` → **`flag_for`**, `_host_from_metric` → **`host_from_metric`**,
  `_series_name` → **`series_name`**. Those were the only three call sites
  (all inside `aggregate()`); nothing else in `src/` or `tests/` referenced them.
- New **`series_identity(metric, guest_names, instance_host_map) -> (host, name) | None`**.
  Promoting the three helpers alone was *not* sufficient for byte-identical
  identity: `aggregate()` also applied two rules inline — the Proxmox guest
  override (a `qemu/`/`lxc/` series is attributed to the **guest**, with an
  empty `name`) and the `ubuntu-server` veth skip. Both are now inside
  `series_identity`, and `aggregate()` calls it, so there is exactly one
  implementation of "who is this series about".
- New **`guest_name_map(metrics)`** — takes bare label dicts, so the same
  `id -> name` extraction serves the daily path's `query_range` matrices and
  the threshold path's instant vectors. `aggregate()` uses it too.
- Added `__all__`.

### `src/heim/config.py` + both settings yamls (A1)
`Settings` gains `threshold_detection: bool = True`,
`threshold_severity: Literal["crit","warn"] = "crit"`,
`threshold_consecutive: int = 2`, each commented. The same three lines (exactly
the spec's block) were appended to `config/settings.example.yaml` and
`config/settings.yaml`; `diff` between the two reports **IDENTICAL**.

### `src/heim/incidents/store.py` (A3)
New `threshold_streaks(fingerprint PK, count, severity, last_seen)` table in
`_SCHEMA` (so it is created on connect, for fresh and deployed databases alike),
plus `threshold_streaks()` / `save_threshold_streaks(rows)` /
`clear_threshold_streaks(fps)`. Read whole rather than per-fingerprint: a poll
evaluates the entire catalog at once and the table only ever holds the handful
of series currently over threshold. Not touched by `prune()` — a streak is live
state, not history.

### `src/heim/incidents/types.py`
New `ThresholdDecision`. Its first four fields mirror `PollerDecision` so the
pipeline applies them with identical machinery; `streak_writes`/`streak_clears`
carry the hysteresis state to persist.

### `src/heim/pipelines/thresholds.py` (new, A2/A3)
- `fetch_instants(base_url, qdefs)` — one `/api/v1/query` per catalog entry,
  `Semaphore(8)`, per-query `neverError`. Deliberately not the 3-day range.
- `build_samples(results, instance_host_map)` — pure. Guest map first, then one
  flagged sample per series via `flag_for` + `series_identity`, fingerprinted
  `f"{norm_host(host)}|{qid}|{name}"` (reconcile's `norm_host`). Failed queries
  contribute nothing; duplicate fingerprints keep the worst flag.
- `ThresholdConfig(severity, consecutive, suppressed)` with
  `from_settings()` and `over_flags` (`warn` ⇒ `("crit","warn")`).
- **`decide(samples, open_rows, streaks, now_iso, routing, cfg)`** — the plan's
  exact signature, no I/O, shaped after `incidents/poller_logic.py`
  (module docstring stating the port/design decisions, `_int`/`_truthy`
  helpers, the same row dict keys, the same Loki event shape, the same
  "missed twice ⇒ resolved" loop).
  - hysteresis: over threshold ⇒ streak+1 write; under threshold ⇒ streak clear
    (so a later crit restarts at 1); `count < consecutive` ⇒ nothing else.
  - ownership: descriptions are `[metric] `-prefixed; the resolve loop skips any
    open row whose description does not start with `[metric] `.
  - existing incident: refreshed (`lastSeen`, `timesSeen`, `missedRuns=0`) and
    never duplicated or re-dispatched; warn→crit escalation is the one exception
    and dispatches once, mirroring the alert poller.
  - investigability/role/ssh-host come from `reconcile.is_investigable`,
    `host_role_for`, `ssh_host_for` and `category_of` — the daily path's own.
  - a crit that is not investigable becomes a notification instead.

### `src/heim/pipelines/suppression.py`
`filter_threshold(dec, suppressed)`, built from the existing `filter_rows` /
`filter_incident_events`, same shape as `filter_decision`.

### `src/heim/pipelines/poller.py` (A4)
Split into `_run_alerts` (the previous body, unchanged in behaviour) and
`_run_thresholds`, both driven by `run_poll` inside **separate `try/except`
blocks** — a failure in one half cannot abort the other, and the alert half's
counters survive a threshold half that explodes. The threshold half is skipped
entirely when `threshold_detection` is false. It shares the store, `rt.notify`,
`rt.emit_loki`, `compute_state` and `dispatch_all(trigger="threshold")`, so the
approval gate, the `max_concurrent_investigations` cap and the mutes apply
unchanged. **Zero samples is treated as "we cannot see", not "all clear"**: no
writes, above all no resolves. Streaks are persisted *before* the incident
writes so a mid-poll failure cannot double-count a streak.
`run_poll` now merges both halves' counters (`threshold_*`) and the "was this
poll worth a `runs` row" check considers both.

### `src/heim/cli.py` (A5)
`heim poll` prints the merged summary (threshold counters included, for free).
New **`heim thresholds [--all]`**: flag · host · metric · current · streak,
worst first, warn/crit only unless `--all`, with a `← opens next poll` marker on
any series one poll short of `threshold_consecutive`. Added to the module
docstring and the dispatch table.

### Part B — `src/heim/dashboard/app.py` + `templates/metrics.html`
`_offenders(payload)` caps `payload["topAlerts"]` (already crit-before-warn,
then `|Δ|` desc — `aggregate` sorts it) at `_OFFENDER_ROWS = 8` and computes
`more` from `counts.crit + counts.warn`, so the `+N more` can never disagree
with the counts beside it. Rendered in `metrics.html` directly under the
`.mline`, only when there is at least one offender: status pill, `m.hostbadge()`,
`label` + mono `--ink-2` device/mount/id, humanized current, the existing
arrow/percentage delta. `+N more` links to `#mall`, an id added to the filters
form — i.e. the full, unabridged per-host tables immediately below.

**CSS: not one new rule.** `src/heim/dashboard/static/heim.css` is still
**20,971 B** against the 20,992 B cap (`tests/test_dashboard.py:446` passes
unchanged). The table reuses `tbl dense` plus the existing `c-flag` / `c-mname` /
`c-cur` / `c-delta` / `num mono ink2` / `ghost` / `hbadge` classes. `.mtbl` is
deliberately *not* applied — its `table-layout: fixed` percentages are tuned for
the six-column per-host tables, and this is a five-column table with a host
column instead of trend/avg.

---

## Evidence

### Fingerprint parity (the test that stops double-investigation)

`tests/test_thresholds.py::test_threshold_and_daily_agree_on_the_fingerprint`
builds **the same series through both pipelines** and compares:

- daily: a real `query_range` matrix for `pve_cpu_usage_ratio{id="qemu/100"}`
  (`8.6 → 12.5 → 102.5`, the observed 3-day averages) → `aggregate()` → payload
  row (asserted `flag == "crit"`) → `reconcile.fingerprint_for()`;
- threshold: the same labels as an instant vector → `build_samples()`.

Parametrised over both identity branches:

| `pve_guest_info` | daily fingerprint | threshold fingerprint |
|---|---|---|
| present (`qemu/100` → `ubuntu-server`) | `ubuntu-server\|pve_vm_cpu\|` | identical |
| absent | `qemu/100\|pve_vm_cpu\|` | identical |

### The spike sequence (driven live, not just asserted)

Replaying the observed 24-sample window (`[20.9]*12 + [102.5] + [21.4]*11`,
`crit: 95`) through the real `decide()`, carrying the streak forward as the
store would:

```
poll=11 value=20.9   streaks={}                             rows=0 dispatch=0
poll=12 value=102.5  streaks={'ubuntu-server|pve_vm_cpu|':1} rows=0 dispatch=0
poll=13 value=21.4   streaks={}                             rows=0 dispatch=0
...total rows opened: 0  dispatches: 0
```

Two consecutive over-threshold polls, same code:

```
poll=1 streak=1 rows=0 dispatch=0
poll=2 streak=2 rows=1 dispatch=1
  [metric] VM CPU on ubuntu-server is 102.5% (crit threshold 95%) — over threshold on 2 consecutive polls
  dispatch -> ubuntu-server|pve_vm_cpu| guest ubuntu-server
```

Pinned by `test_the_observed_spike_never_dispatches` and
`test_second_consecutive_crit_poll_opens_and_dispatches`.

### `/metrics` header, rendered in-process (TestClient, no server, no curl)

```html
<span class="mono counts">1 crit · 1 warn · 1 no-data</span>
...
<table class="tbl dense">
 <tr>
  <td class="c-flag"><span class="pill st-crit">…crit</span></td>
  <td><span class="hbadge">…ubuntu-server</span></td>
  <td class="c-mname">Drive temp <span class="mono ink2">sdb</span></td>
  <td class="num mono c-cur">68.0°C</td>
  <td class="num mono c-delta st-crit">▲ 13.3%</td>
 </tr>
 <tr>… ubuntu-server · Memory used · 91.0% · ▲ 11.0% (warn) …</tr>
</table>
```

The header now names the host **and** the resource (device included), crit
before warn.

---

## New tests

`tests/test_thresholds.py` (23):
`test_samples_carry_the_flag_and_the_guest_identity`,
`test_an_unnamed_guest_keeps_its_id_as_the_host`,
`test_a_failed_query_contributes_no_samples`,
`test_below_threshold_decides_nothing`,
`test_first_crit_poll_only_starts_a_streak`,
`test_second_consecutive_crit_poll_opens_and_dispatches`,
`test_the_observed_spike_never_dispatches`,
`test_a_clear_poll_clears_the_streak`,
`test_two_clear_polls_resolve_a_metric_incident`,
`test_foreign_incidents_are_neither_resolved_nor_duplicated[[alert] …]`,
`test_foreign_incidents_are_neither_resolved_nor_duplicated[CPU is climbing]`,
`test_warn_to_crit_escalates_and_dispatches_once`,
`test_suppressed_fingerprints_are_skipped_entirely`,
`test_threshold_severity_warn_includes_crit`,
`test_a_non_investigable_crit_notifies_instead_of_dispatching`,
`test_threshold_and_daily_agree_on_the_fingerprint[True-ubuntu-server]`,
`test_threshold_and_daily_agree_on_the_fingerprint[False-qemu/100]`,
`test_streaks_upsert_clear_and_persist`,
`test_settings_ship_threshold_detection_on`,
`test_the_poll_runs_both_halves_and_persists_the_streak`,
`test_threshold_detection_off_skips_the_half`,
`test_each_half_survives_the_other_failing`,
`test_an_unreachable_prometheus_never_resolves_a_metric_incident`.

`tests/test_metrics_page.py` (4):
`test_header_names_the_offending_host_and_resource`,
`test_header_table_is_absent_when_nothing_is_flagged`,
`test_header_table_caps_and_links_to_the_rest`,
`test_offenders_never_disagree_with_the_counts`.

---

## Judgment calls

1. **`series_identity` was necessary.** Importing the three named helpers alone
   would have produced a *different* host for every Proxmox guest series —
   exactly the `pve_vm_cpu` / `qemu/100` case the feature exists for. Folding
   the guest override and the veth skip into one shared function is what makes
   the parity test pass on both branches.
2. **An existing incident is refreshed on every over-threshold poll**
   (`lastSeen`, `timesSeen`, `missedRuns=0`), per the plan's "update
   lastSeen/timesSeen only". The alert poller writes nothing in that case. To
   keep the churn honest, `ThresholdDecision.state_changed` is True only for
   **new / escalated / resolved** rows — a `lastSeen` refresh must not emit a
   Loki state snapshot every five minutes, and must not make an otherwise idle
   poll insert a `runs` row.
3. **Suppression is applied twice, deliberately.** `decide()` takes the muted
   set on `ThresholdConfig` (it has to: a muted series must not silently
   accumulate a streak, and must not be resolved out from under the mute), and
   the pipeline additionally runs `suppression.filter_threshold`, so the
   "nothing muted reaches the store/Telegram/Loki/investigator" guarantee holds
   for any caller, as it does for the other two paths.
4. **Zero samples ⇒ do nothing.** Mirrors the poller's `aborted` rule: an
   unreachable Prometheus is not "everything is under threshold", and a false
   resolve is the worst outcome available. Test:
   `test_an_unreachable_prometheus_never_resolves_a_metric_incident`.
5. **The offenders table describes the whole payload, like the counts above it**
   — spec §6 already says the header stays put when a filter narrows the tables
   (`test_filters_that_match_nothing_say_so`). The two existing filter tests
   asserted `"Memory used" not in <whole page>`; they now assert it against the
   *tables* (`_tables()` splits at `#mall`), which is the tighter assertion and
   the one they actually meant. No assertion was dropped.
6. **`+N more` links to `#mall`**, the anchor on the filters form immediately
   above the full per-host tables. There is no flag filter on `/metrics` to link
   to, and the overflow rows span hosts, so no single host/category query is the
   "filtered view"; the unabridged tables are.
7. **`heim poll`'s summary gained keys.** Two fixtures (`tests/test_tracking.py`,
   `tests/test_jobs.py`) now set `cfg.settings.threshold_detection = False` —
   those tests are about the alert half and would otherwise open ~49 real
   sockets to a non-routable test IP. One line each, commented.

## Concerns

- **`heim thresholds` and `fetch_instants` have no unit test that hits the real
  HTTP path.** `fetch_instants` is monkeypatched in the pipeline tests and the
  CLI command is only parser-checked (`heim thresholds --help` verified). The
  per-query `neverError` shape is copied from `daily._fetch_query_ranges`, which
  is covered, but the instant-vector *response* parsing (`_vector`/`_value`) is
  only exercised through synthetic fixtures — a real Prometheus was not
  available here.
- `decide()` writes one `incidents` row per poll per open `[metric] ` incident
  (judgment call 2). At the default 5-minute cadence that is 288 writes/day per
  open threshold incident and a `timesSeen` that counts polls, not days. It is
  what the plan asked for and it is cheap in SQLite, but it is a different
  meaning of `timesSeen` than the daily path's (which counts *runs*).
- `threshold_severity: warn` is implemented and tested but untried in anger; on
  a real catalog it would arm every warn-flagged series in the deployment at
  once. The shipped default is `crit`.
- Streak rows are never garbage-collected for fingerprints that vanish from the
  catalog (a removed query, a deleted VM). They are cleared the moment the
  series reports under threshold, but a series that simply stops existing leaves
  a row behind. Harmless (it is keyed by fingerprint and only read for series
  that report), but it is unbounded in the pathological case.

---

# Addendum — CRITICAL: three-way fingerprint parity

## The finding, reproduced

The reviewer was right and my original parity test was too narrow: it compared
the threshold path against the **daily** path only, never against the **alert
poller**. Reproduced directly over every qid present in *both*
`config/queries/daily.yaml` and `prometheus/alerts.yml` (16 of them):

```
DIVERGE pve_node_up     poller homelab|pve_node_up|node/homelab
                        metrics homelab|pve_node_up|
DIVERGE pve_pool_up     poller homelab|pve_pool_up|storage/local-lvm
                        metrics homelab|pve_pool_up|local-lvm
DIVERGE pve_pool_used   poller homelab|pve_pool_used|storage/local-lvm
                        metrics homelab|pve_pool_used|local-lvm
DIVERGE pve_vm_up       poller homelab|pve_vm_up|qemu/100
                        metrics ubuntu-server|pve_vm_up|
8 divergent combination(s) of 32
```

Exactly the four `pve_`-prefixed shared qids, and only those — the other twelve
(`fs_used`, `smart_status`, `drive_temp`, `cpu_busy`, …) already agreed. As the
reviewer noted, this predates my change: `poller_logic._name_for` embedded the
raw `id` verbatim while `aggregate` blanked `node/`/`cluster/` ids, stripped the
`storage/` prefix and attributed a guest series to the guest. I inherited the
daily convention and so inherited the disagreement.

## Red before green (ruling item 4)

`test_all_three_paths_agree_on_the_fingerprint` was written first and run
against unmodified code:

```
E       AssertionError: alert poller
E       assert 'homelab|pve_node_up|node/homelab' == 'homelab|pve_node_up|'
E       AssertionError: alert poller
E       assert 'homelab|pve_pool_used|storage/local-lvm' == 'homelab|pve_pool_used|local-lvm'
E       AssertionError: alert poller
E       assert 'homelab|pve_vm_up|qemu/100' == 'ubuntu-server|pve_vm_up|'
FAILED tests/test_thresholds.py::test_all_three_paths_agree_on_the_fingerprint[pve_node_up]
FAILED tests/test_thresholds.py::test_all_three_paths_agree_on_the_fingerprint[pve_pool_used]
FAILED tests/test_thresholds.py::test_all_three_paths_agree_on_the_fingerprint[pve_vm_up]
3 failed, 2 passed, 23 deselected
```

The two that passed are the non-pve shapes (`fs_used`, `smart_status`) — the
test was red for exactly the right reason, and green for the right reason too.

## The fix — one implementation, three callers (ruling items 1 & 2)

`src/heim/incidents/poller_logic.py`
- `_name_for` no longer handles `pve_` qids at all; the branch is deleted and
  the docstring says where identity comes from instead.
- New `_identity_for(qid, labels, guest_names, instance_host_map, hypervisor_host)`
  delegates to **`aggregate.series_identity`** — the same function `aggregate()`
  and `pipelines.thresholds` call. It returns both host *and* name, so the
  guest override (`qemu/100` → the guest, not the hypervisor) applies to alerts
  too.
- The firing-set loop now branches `container_*`/`n8n_net_spike` → `_name_for`,
  `pve_*` → `_identity_for`, everything else → `_name_for`, and the stale
  unconditional `nm = _name_for(...)` that used to follow was removed.
- `diff_and_decide` gained `guest_names: dict[str, str] | None = None`.

**The one call-site adaptation** (ruling item 2): an *alert* need not carry a
usable `instance` label the way a *series* does, and the poller's long-standing
rule is that a PVE object belongs to the hypervisor. So when `series_identity`
cannot resolve a host (`"unknown"`), `_identity_for` falls back to
`routing.hypervisor_host`. Nothing else is forked — the naming rules are not
reimplemented anywhere.

`src/heim/pipelines/poller.py` — supplies the guest map:
- `_has_guest_alert(resp)` + `_guest_names(rt, resp)`: the map is fetched **only
  when a firing alert actually carries a `qemu/`/`lxc/` id**, so the common poll
  pays nothing. On any failure it degrades to `{}`, which yields the raw id —
  still *identical* across all three paths, just less readable, never a second
  identity.

`src/heim/pipelines/thresholds.py` — `fetch_guest_names(base_url, qdefs)`: takes
the catalog, queries exactly the one `pve_guest_info` entry. `GUEST_INFO_QID`
replaces the three literal spellings of that qid.

No migration code: per the controller, the live instance has no open incidents,
so there is no fingerprint continuity to preserve.

## Verification

Full suite:

```
.venv/bin/pytest -q
743 passed, 12 warnings in 19.57s
```

Direct three-way sweep after the fix, same harness that produced the red output
above:

```
0 divergent of 32 (all 16 qids present in BOTH daily.yaml and alerts.yml)
```

## Tests added / ported

- `test_all_three_paths_agree_on_the_fingerprint[pve_node_up|pve_pool_used|pve_vm_up|fs_used|smart_status]`
  — builds the fingerprint through **all three** paths for one underlying event
  (daily `aggregate` + `reconcile.fingerprint_for`; alert poller
  `diff_and_decide`; threshold `build_samples`) and asserts all three equal.
  Covers the `node/` shape, the `storage/` shape, the guest `qemu/` shape and
  two non-pve shapes (device+mountpoint, bare device).
- `tests/test_poller_logic.py::test_pve_id_label_falls_back_to_hypervisor_host`
  — **ported, not deleted**. Its intent (a PVE object maps to the hypervisor) is
  still asserted, now via the case where it genuinely still holds: an alert with
  no usable `instance` label. It additionally pins the unified naming
  (`storage/local-lvm` → `local-lvm`) and still asserts the dispatch.
- `test_pve_object_resolves_its_host_from_the_instance_label` (new) — with an
  instance label the shared helper decides, and lands on the same host.
- `test_a_pve_guest_alert_is_attributed_to_the_guest` (new) — the guest override
  in the poller, with and without the guest map.
- `test_fetch_guest_names_asks_for_one_query_not_the_catalog`,
  `test_a_guest_alert_fetches_the_guest_map_exactly_once`,
  `test_a_poll_with_no_guest_alert_never_fetches_the_guest_map`,
  `test_a_failing_guest_map_degrades_to_the_raw_id` (new) — the call site.

## `timesSeen` semantics (non-blocking item)

- `docs/design/dashboard-ui.md` §3 "Incidents": `seen ×N` counts sightings by
  the path that owns the row, and the cadences differ (`[metric] ` ~288/day,
  `[alert] ` on state change, daily 2/day) — compare within an ownership prefix,
  never across.
- `thresholds.decide`, at the `timesSeen` write site: the same note, pointing at
  the spec section.

## Concerns (new, from this fix)

- **A PVE guest alert can now dispatch where it previously only notified.**
  `pve_vm_up` on `qemu/100` used to resolve to host `homelab` with category
  `other` → not investigable → Telegram notification. It now resolves to the
  guest (`ubuntu-server`), which *is* an SSH host → investigable → dispatch. For
  a **down** VM that means an agent run whose SSH will fail. It is the direct,
  intended consequence of unifying identity (the daily and threshold paths
  already treat that series as the guest's), and the human approval gate still
  sits in front of it — but it is a live behaviour change, not just a renaming.
- **The `id ⇒ hypervisor` rule now yields to the instance label** for non-pve
  qids carrying an `id` (previously any `id` label forced the hypervisor). No
  rule in the shipped `alerts.yml` produces that combination, so this is
  latent — but a future rule that sets an `id` on a non-`pve_` qid would route
  differently than before.
- **PVE host attribution still comes from the exporter's `instance`.** In a
  topology where `pve_exporter` runs as a sidecar on a *different* box than the
  Proxmox node, all three paths would agree on a *wrong* host. The shipped
  config runs the exporter at the Proxmox IP, so this is moot here; it is a
  property of the `aggregate` convention the ruling unified on, not new.
- The guest map is fetched per poll that has a guest alert (not cached across
  polls). One extra instant query while such an alert is firing; zero otherwise.
