# Uptime Kuma Alert Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** HEIM polls Uptime Kuma every 5 minutes, opens an `[uptime]` incident for each down monitor, and tells the operator on Telegram:
- one message per host;
- an approval-gated investigation for investigable hosts;
- report-only for the rest;
- recovery, flapping and "Uptime Kuma unreachable" handled as designed.

**Architecture:**
- A third, independent half of the existing poll cycle (`pipelines/poller.run_poll`), modelled on the threshold half.
- Pure decision logic lives in `src/heim/incidents/uptime_logic.py`, unit-tested.
- I/O (fetch, store writes, notify, dispatch) lives in `src/heim/pipelines/uptime.py`.
- Investigation plumbing in `pipelines/investigate.py` gains:
  - group findings and a headline;
  - folding new findings into a pending investigation;
  - re-reading the stored row after approval;
  - a note on checks that have recovered;
  - unlocking every incident in a group on decline.

**Tech Stack:** Python 3.13, asyncio, httpx, pydantic settings, SQLite (`IncidentStore`), pytest (asyncio mode), Jinja briefs.

**Spec:** `docs/superpowers/specs/2026-11-01-uptime-kuma-design.md`. Read it before Task 1; this plan argues from it.

Work on branch `feat/uptime-kuma`, created from `main`.

## Global Constraints

- **No deployment identity in git** (the repo is public). The URL comes from `${HEIM_UPTIME_KUMA_URL:-}` (empty = feature off) and the API key from env `UPTIME_KUMA`. No IP, URL or key goes in code, config, tests or docs; tests use `10.0.0.x` addresses.
- **Auth.** `GET <url>/metrics` with HTTP basic auth: empty username, the key as the password. Bearer auth is not used.
- **Kuma status values:** `0` down, `1` up, `2` pending, `3` maintenance.
- **Identifiers:**
  - prefix `PREFIX = "[uptime] "`;
  - qid `uptime_down`, and `uptime_kuma_up` for the unreachable incident;
  - category `availability`;
  - investigation trigger `"uptime"`.
- **Fingerprints:** `"{host}|uptime_down|{monitor name}"`, with any `|` in the name replaced by `/`. The unreachable incident is `"{kuma_host}|uptime_kuma_up|"`.
- **Constants:** `RESOLVE_AFTER = 2` up polls; `ABSENT_AFTER = 2` successful polls without the monitor; `UNREACHABLE_AFTER = 2` failed polls; `FLAP_WINDOW_S = 3600`; flap lines at most every 3600 s per monitor.
- **Severity:** every monitor outage is `critical`. The unreachable incident is `warning` and report-only.
- **Exact Telegram copy.** `{items}` is `", ".join(f"{name} ({target})")`; `{hhmm}` is `firstSeen` in `settings.timezone`; `{minutes}` is `max(1, round(down seconds / 60))`.
  - New outage: `🔴 Down on {host}: {items} · first seen {hhmm}`
  - Report-only suffix: `\n(report only: not a HEIM host)` for an unmapped address; `\n(report only: no investigation for this host)` for a HEIM host that isn't investigable.
  - Joining a pending investigation: `🔴 Also down on {host}: {items} · added to pending investigation #{id}`
  - Recovery, one per host per poll: `✅ Back up on {host}: {name} (down {minutes} min), {name2} (down {m2} min)`
  - Paused or removed: `⏸ {name} on {host} is no longer monitored (paused or removed): closing its outage`
  - Flapping: `🔁 {name} on {host} keeps flapping ({n} outages since {hhmm})`
  - Stable again: `✅ {name} on {host} stable again after {n} outages`
  - Uptime Kuma unreachable: `⚠️ Can't reach Uptime Kuma: service outages are not being watched.`
  - Uptime Kuma back: `✅ Uptime Kuma is reachable again: watching service outages.`
- **Investigable hosts:**
  - hosts in `routing.ssh_hosts`;
  - `routing.ha_host`;
  - `routing.hypervisor_host` when `"availability"` is in `routing.hypervisor_categories`.

  Everything else is report-only.
- **Ownership.** This path reads, refreshes and resolves only open rows whose `description` starts with `PREFIX` (AGENTS.md invariant 3).
- **Dry-run.** In dry-run (`rt.dry_run`) the uptime half writes nothing: no incidents, monitor state or fail counter.
- **Side channels.** Telegram and Loki failures never propagate. An exception in the uptime half never stops the alert or threshold half.
- **Tests.** `.venv/bin/pytest -q` stays green. The one known failure, `test_both_settings_yamls_document_the_new_knobs`, reads the local gitignored `config/settings.yaml` and is pre-existing.

## Review Focus

1. **Address prefix collision.** A k8s node at `10.0.0.24` while the Proxmox host is `10.0.0.2`: the k8s node must be report-only, never mapped to homelab (Task 1 test).
2. **Uptime Kuma restarting.** Right after a restart the export lists only some monitors: an outage missing for one poll must stay open, with no "paused" note and no reopen (Task 3 test).
3. **Odd monitor names.** Escaped quotes (`My \"prod\" app`), commas, or a `|` in the name: parsing must keep the exact name, and the fingerprint must stay three-part (Tasks 1 and 3 tests).
4. **Uptime Kuma unreachable while an outage is open.** No resolve and no recovery message. When Uptime Kuma returns with the monitor still down, there is no second "down" message (Task 3 test). The daily run must not close it meanwhile (Task 7 test).
5. **A daemon restart mid-flap or mid-unreachable count.** The flap state and the fail counter come back from the store, and behaviour is identical (Task 4 test).

---

### Task 1: Parse `/metrics` and map monitors to hosts

**Files:**
- Create: `src/heim/incidents/uptime_logic.py`
- Test: `tests/test_uptime_logic.py`

**Interfaces:**
- Produces:
  - constants `PREFIX`, `QID`, `KUMA_QID`, `CATEGORY`, and `DOWN, UP, PENDING, MAINTENANCE = 0, 1, 2, 3`
  - `@dataclass(frozen=True) class Monitor: monitor_id: str; name: str; type: str; target: str; address: str; status: int`
  - `parse_metrics(text: str) -> list[Monitor]`
  - `target_of(labels: dict[str, str]) -> tuple[str, str]`, returning `(target, address)`
  - `map_host(address: str, instance_host_map: dict[str, str], host_names: Iterable[str]) -> str | None`
  - `is_investigable_host(host: str, routing: HostRouting) -> bool`
  - `unmapped_monitors(monitors: list[Monitor], instance_host_map: dict[str, str], host_names: Iterable[str]) -> list[Monitor]`
  - `is_uptime_row(row: dict) -> bool`, true when `description` starts with `PREFIX`

- [ ] **Step 1: Write the failing tests** in `tests/test_uptime_logic.py`, using a small inline `/metrics` text fixture with `# HELP` lines, `monitor_response_time` lines and three `monitor_status` lines:
  - `test_parse_reads_status_and_labels`:
    - http monitor `n8n` on `http://10.0.0.10:5678`, status 0, gives `Monitor("1","n8n","http","http://10.0.0.10:5678","10.0.0.10",0)`;
    - port monitor (`monitor_url="https://"`, hostname `10.0.0.10`, port `22`) gives target `"10.0.0.10:22"`, address `"10.0.0.10"`;
    - ping monitor (port `"null"`) gives target `"10.0.0.10"`.
  - `test_parse_unescapes_label_values`: `monitor_name="My \"prod\" app, v2"` gives name `'My "prod" app, v2'`.
  - `test_parse_returns_nothing_without_monitor_status`: text with only `app_version` and response-time lines gives `[]`.
  - `test_map_host_matches_the_whole_address_not_a_prefix`, with map `{"10.0.0.10": "ubuntu-server", "10.0.0.2": "homelab"}`:
    - `"10.0.0.24"` gives `None`;
    - `"10.0.0.2"` gives `"homelab"`;
    - `"10.0.0.10"` gives `"ubuntu-server"`.
  - `test_map_host_by_first_dns_label`, with host names `{"ubuntu-server", "homelab"}`:
    - `"ubuntu-server.tail1234.ts.net"` gives `"ubuntu-server"`;
    - `"Ubuntu-Server.example"` gives `"ubuntu-server"`;
    - `"grafana.example"` gives `None`.
  - `test_investigability`, with `HostRouting(ssh_hosts=frozenset({"ubuntu-server"}), hypervisor_host="homelab", hypervisor_categories=frozenset({"cpu","availability"}), ha_host="home-assistant")`:
    - ubuntu-server, home-assistant and homelab are `True`;
    - the same routing without `"availability"` makes homelab `False`;
    - `"heim"` and `"10.0.0.24"` are `False`.
  - `test_unmapped_monitors_lists_report_only_targets`: monitors on `10.0.0.10` and `10.0.0.24` give only the `10.0.0.24` one.

- [ ] **Step 2: Run the tests to verify they fail**

  Run: `.venv/bin/pytest tests/test_uptime_logic.py -q`. Expected: FAIL (module not found).

- [ ] **Step 3: Implement `uptime_logic.py` (parsing, mapping, investigability)**
  - **Parsing.** Only `monitor_status{…} <value>` lines. Label values are double-quoted, with `\"`, `\\` and `\n` escapes. A non-numeric value skips the line.
  - **`target_of`.** Use `monitor_url` when it has a scheme *and* a non-empty host (so not `""`, `"null"`, `"https://"` or `"http://"`). Otherwise use `monitor_hostname`, plus `:{port}` when the port is not `""` or `"null"`. The address is the lowercased hostname: `urlsplit(...).hostname` for URLs.
  - **`map_host`.** An IP literal (per `ipaddress.ip_address`) matches the map key whose `split(":")[0]` **equals** it. Never `startswith`: that is the review-focus collision. A hostname matches the host name equal to its first label, case-insensitively.
  - Module docstring: say this is the pure half of the Uptime Kuma source and point to the spec.

- [ ] **Step 4: Run the tests to verify they pass**

  Run: `.venv/bin/pytest tests/test_uptime_logic.py -q`. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/heim/incidents/uptime_logic.py tests/test_uptime_logic.py docs/superpowers/specs/2026-11-01-uptime-kuma-design.md docs/superpowers/plans/2026-11-01-uptime-kuma.md
git commit -m "uptime: parse Uptime Kuma's /metrics and map monitors to hosts"
```

### Task 2: Persist monitor state and the fail counter

**Files:**
- Modify: `src/heim/incidents/store.py`: the `_SCHEMA` string (add two tables after `threshold_streaks`), and methods next to `threshold_streaks()` (around line 999)
- Test: `tests/test_uptime_logic.py` (store section)

**Interfaces:**
- Produces, as `IncidentStore` methods:
  - `uptime_states() -> dict[str, dict]`, keyed by fingerprint; each value has the keys `fingerprint, up_polls, absent_polls, last_recovered_at, flap_outages, flap_msg_at`
  - `save_uptime_states(rows: list[dict]) -> None`, an upsert
  - `clear_uptime_states(fingerprints) -> int`
  - `uptime_fail_polls() -> int`, `0` when unset
  - `set_uptime_fail_polls(n: int) -> None`
- Schema:
  - `uptime_monitors(fingerprint TEXT PRIMARY KEY, up_polls INTEGER NOT NULL DEFAULT 0, absent_polls INTEGER NOT NULL DEFAULT 0, last_recovered_at TEXT NOT NULL DEFAULT '', flap_outages INTEGER NOT NULL DEFAULT 0, flap_msg_at TEXT NOT NULL DEFAULT '')`
  - `uptime_source(id INTEGER PRIMARY KEY CHECK (id = 1), fail_polls INTEGER NOT NULL DEFAULT 0)`

- [ ] **Step 1: Write the failing tests**
  - `test_uptime_states_round_trip_and_survive_reopen(tmp_path)`: save two rows, then update one. A **new** `IncidentStore` on the same file returns both with the updated values. `clear_uptime_states([fp])` returns `1` and removes it.
  - `test_fail_polls_default_and_persist(tmp_path)`: a fresh store gives `0`; `set_uptime_fail_polls(2)` then a reopened store gives `2`.
- [ ] **Step 2: Run the tests.** `.venv/bin/pytest tests/test_uptime_logic.py -q -k "uptime_states or fail_polls"`. Expected: FAIL (`AttributeError`).
- [ ] **Step 3: Implement the two tables and five methods,** mirroring the `threshold_streaks` methods (commit after each write).
- [ ] **Step 4: Run the tests.** Same command. Expected: PASS. Then `.venv/bin/pytest -q tests/test_tracking.py tests/test_thresholds.py`: PASS (nothing else in the store changed).
- [ ] **Step 5: Commit**

```bash
git add src/heim/incidents/store.py tests/test_uptime_logic.py
git commit -m "store: persist Uptime Kuma monitor state and the unreachable counter"
```

### Task 3: The decision (open, refresh, resolve, absent, unreachable, grouping)

**Files:**
- Modify: `src/heim/incidents/uptime_logic.py`
- Test: `tests/test_uptime_logic.py`

**Interfaces:**
- Consumes: Task 1's `Monitor`, `map_host` and `is_investigable_host`; the state dict shape from Task 2.
- Produces:
  - `fingerprint(host: str, monitor_name: str) -> str`
  - `@dataclass(frozen=True) class UptimeContext: instance_host_map: dict[str, str]; host_names: frozenset[str]; routing: HostRouting; kuma_host: str; timezone: str; suppressed: frozenset[str] = frozenset(); pending_by_host: dict[str, int] = field(default_factory=dict)`
  - `@dataclass class DownGroup: host: str; rows: list[dict]; investigable: bool; pending_investigation_id: int | None; headline: str; findings: list[dict]`
  - `@dataclass class UptimeDecision: rows_to_upsert: list[dict]; state_writes: list[dict]; state_clears: list[str]; fail_polls: int; groups: list[DownGroup]; messages: list[str]; loki_events: list[dict]; state_changed: bool`
  - `decide(monitors: list[Monitor] | None, open_rows: list[dict], states: dict[str, dict], fail_polls: int, now_iso: str, ctx: UptimeContext) -> UptimeDecision`. `monitors=None` means the poll failed (the I/O layer passes `None` for a fetch error **and** for an empty parse).
- Row contract for a newly opened outage: `fingerprint, host, metric=<name>, severity="critical", status="open", firstSeen=lastSeen=now, resolvedAt="", timesSeen=1, missedRuns=0, description=f"{PREFIX}{name} ({type} {target}) is down in Uptime Kuma", investigated=<investigable>`.
- Finding contract, one per row in `DownGroup.findings`: `{"severity": "critical", "host": host, "metric": name, "trend": "", "fingerprint": fp, "recommendation": "", "detail": f"Uptime Kuma check '{name}' ({type} {target}) has been failing since {hhmm}. Find which container or process on {host} serves {target}, whether it is running, its recent logs, and why it stopped."}`
- Loki events: the same `incident` event shape as `heim.pipelines.thresholds._incident_event`, with category `availability` and statuses `new` and `resolved`. Copy the shape; don't import from pipelines.

- [ ] **Step 1: Write the failing tests.** Use `now = "2026-11-01T02:02:00+00:00"`, timezone `"UTC"`, and a ctx whose map is `{"10.0.0.10": "ubuntu-server", "10.0.0.2": "homelab", "10.0.0.4": "heim", "10.0.0.3": "home-assistant"}`, `kuma_host="home-assistant"`, with the Task 1 routing. Add a helper `_mon(name, status, addr="10.0.0.10", type_="http")`.
  - `test_first_down_poll_opens_a_critical_incident_and_one_group`: one group, host `ubuntu-server`, investigable, headline `"🔴 Down on ubuntu-server: n8n (http://10.0.0.10:5678) · first seen 02:02"`, one row matching the row contract.
  - `test_three_down_monitors_on_one_host_are_one_group`: one group with three rows and three findings, all names in the headline.
  - `test_already_open_outage_is_refreshed_not_regrouped`: an open `[uptime]` row plus DOWN gives an upsert with a new `lastSeen` and `timesSeen+1`, and `groups == []`.
  - `test_two_up_polls_resolve_with_one_grouped_recovery`:
    - the first UP poll leaves the row open, writes state `up_polls=1`, and sends no message;
    - the second resolves it (`status="resolved"`, `resolvedAt=now`) with message `"✅ Back up on ubuntu-server: n8n (down 10 min)"`. Here `firstSeen` is 10 min before `now`, and the state write has `last_recovered_at=now`.
  - `test_pending_and_maintenance_change_nothing`: an open row and statuses 2 and 3 give no resolve, no message, and an unchanged `up_polls`.
  - `test_missing_for_one_poll_stays_open`: an open row and the monitor absent once gives the row still open, `absent_polls=1`, and no message.
  - `test_missing_for_two_polls_closes_with_the_paused_note`: resolved, message `"⏸ n8n on ubuntu-server is no longer monitored (paused or removed): closing its outage"`, and the state cleared.
  - `test_unmapped_address_is_report_only`: `10.0.0.24` gives group host `"10.0.0.24"`, `investigable=False`, and a headline ending in `"\n(report only: not a HEIM host)"`.
  - `test_heim_is_report_only`: `10.0.0.4` gives a headline ending in `"\n(report only: no investigation for this host)"`.
  - `test_new_downs_join_a_pending_investigation`: with `pending_by_host={"ubuntu-server": 41}`, `group.pending_investigation_id == 41`, and the headline is `"🔴 Also down on ubuntu-server: n8n (http://10.0.0.10:5678) · added to pending investigation #41"`.
  - `test_unreachable_never_resolves_or_touches_monitor_state`: `monitors=None` with an open row gives no upsert for that row, empty `state_writes`, `fail_polls == 1` and no messages.
  - `test_second_failed_poll_opens_the_kuma_incident_once`:
    - `fail_polls=1` → result 2, an upserted row with fingerprint `"home-assistant|uptime_kuma_up|"` (severity `warning`, `investigated=False`), and exactly the unreachable message;
    - `fail_polls=2` with that row open → result 3 and no message.
  - `test_kuma_back_resolves_its_incident_and_keeps_open_outages_quiet`: a successful poll with the kuma row open, plus an open n8n row still DOWN, gives the kuma row resolved, `fail_polls == 0`, messages exactly `["✅ Uptime Kuma is reachable again: watching service outages."]` and no groups.
  - `test_suppressed_fingerprints_are_skipped`: suppressing `ubuntu-server|uptime_down|n8n` gives no rows, no groups and no messages for it.
  - `test_foreign_rows_are_never_touched`: an open row with the same fingerprint but an `[alert] ` description gives no upsert for it, while UP polls continue.
  - `test_pipe_in_a_name_keeps_three_fingerprint_parts`: name `"a|b"` gives `fingerprint("ubuntu-server", "a|b") == "ubuntu-server|uptime_down|a/b"`.
- [ ] **Step 2: Run the tests.** `.venv/bin/pytest tests/test_uptime_logic.py -q`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement `fingerprint`, the context and decision dataclasses, and `decide`** per the spec's "Incidents", "Telegram" and "Uptime Kuma unreachable" sections and the copy in Global Constraints.
  - Down-minutes for recovery come from the row's `firstSeen`.
  - Group recoveries per host, in first-seen order.
  - State writes keep `last_recovered_at` after a resolve; Task 4 relies on it. Remove a monitor's state when it has no open row, no flap episode and a `last_recovered_at` older than `FLAP_WINDOW_S`.
  - Record a flap-free placeholder for Task 4: `flap_outages` stays `0` here.
- [ ] **Step 4: Run the tests.** Same command. Expected: PASS.
- [ ] **Step 5: Commit**

```bash
git add src/heim/incidents/uptime_logic.py tests/test_uptime_logic.py
git commit -m "uptime: decide outages, recoveries and the unreachable alert"
```

### Task 4: Flapping

**Files:**
- Modify: `src/heim/incidents/uptime_logic.py` (`decide`)
- Test: `tests/test_uptime_logic.py`

**Interfaces:**
- Consumes: Task 3's `decide` and the state fields `last_recovered_at`, `flap_outages` and `flap_msg_at`.
- Produces: no new names. `decide` gains the flap rules below.

Rules (from the spec, decided with the operator):
- **A new outage within the window.** If `last_recovered_at` is within `FLAP_WINDOW_S` of now, there is no group. Reopen the **same** row: `status="open"`, keep `firstSeen`, `resolvedAt=""`, keep `investigated`. Set `flap_outages = max(flap_outages, 1) + 1`. If `flap_msg_at` is empty or at least 3600 s old, send the flap line and set `flap_msg_at=now`.
- **A resolve while flapping** (`flap_outages > 0`) sends no recovery message.
- **Stable again.** When the monitor is UP with no open row, `flap_outages > 0` and `last_recovered_at` is at least `FLAP_WINDOW_S` old: send the stable line with `n = flap_outages` and clear the state.

- [ ] **Step 1: Write the failing tests**
  - `test_down_within_an_hour_reopens_quietly_with_one_flap_line`: `last_recovered_at = now − 20 min` plus DOWN gives no groups, the row reopened with its old `firstSeen`, messages `["🔁 n8n on ubuntu-server keeps flapping (2 outages since 01:52)"]`, and state `flap_outages=2`, `flap_msg_at=now`.
  - `test_flap_lines_are_at_most_hourly`: `flap_msg_at = now − 30 min` and `flap_outages=2` plus DOWN gives no message and `flap_outages=3`.
  - `test_recovery_while_flapping_is_silent`: two UP polls while `flap_outages=3` give the row resolved and no messages.
  - `test_an_hour_up_ends_the_flap_with_one_stable_line`: no open row, `flap_outages=3`, `last_recovered_at = now − 61 min` and UP give `["✅ n8n on ubuntu-server stable again after 3 outages"]`, with the fingerprint in `state_clears`.
  - `test_down_more_than_an_hour_after_recovery_is_a_new_outage`: `last_recovered_at = now − 61 min`, not flapping, plus DOWN gives one group as in Task 3.
  - `test_flap_state_survives_a_restart(tmp_path)`:
    - run `decide` and save its `state_writes` with `IncidentStore.save_uptime_states`;
    - reopen the store;
    - pass `uptime_states()` to the next `decide`.

    The second outage's result equals the in-memory run's.
- [ ] **Step 2: Run the tests.** `.venv/bin/pytest tests/test_uptime_logic.py -q -k flap`. Expected: FAIL.
- [ ] **Step 3: Implement the flap rules in `decide`.**
- [ ] **Step 4: Run the tests.** `.venv/bin/pytest tests/test_uptime_logic.py -q`. Expected: all PASS.
- [ ] **Step 5: Commit**

```bash
git add src/heim/incidents/uptime_logic.py tests/test_uptime_logic.py
git commit -m "uptime: reopen a flapping monitor quietly, one line an hour"
```

### Task 5: Investigation plumbing for groups

**Files:**
- Modify: `src/heim/pipelines/investigate.py`:
  - `InvestigationRequest` (line 87)
  - `_approval_text` (line 135)
  - `run_investigation` (brief rendering around line 452; the approval and decline block around lines 506–530; the needs-human reset around line 686)
  - `request_from_dispatch` (line 692)
- Test: `tests/test_uptime_investigation.py`

**Interfaces:**
- Consumes: findings shaped per Task 3, each carrying `fingerprint`.
- Produces:
  - `InvestigationRequest.headline: str = ""`. When set, `_approval_text` starts with `f"{headline}\n\n"` before the existing text.
  - `request_from_dispatch(item, rt)`: a non-empty `item["findings"]` list is used as-is, and `headline=str(item.get("headline") or "")`. Old items behave exactly as before.
  - `_render_brief(cfg, jenv, req: InvestigationRequest) -> str`: the existing brief rendering, extracted with identical output.
  - `extend_pending_investigation(rt, investigation_id: int, findings: list[dict]) -> bool`. It returns `False` unless the row's status is `pending_approval`. Otherwise it merges stored and new findings (deduplicated by `fingerprint`), re-renders the brief from `request_from_investigation(row)` with the merged findings, writes `findings_json` and `brief_md`, and returns `True`.
  - `recovered_note(store, findings: list[dict]) -> str`. It returns `""` when no finding's incident is resolved. Otherwise it returns `"\n\nNote: since this investigation was proposed, these checks have recovered: {names}. Find out why they went down."`, with names comma-joined in findings order.
  - `_lock_fingerprints(req) -> list[str]`: unique, `req.fingerprint` first, then every finding's `fingerprint`.
  - In `run_investigation`, right after `_await_approval` returns (both branches), re-read the row. `req.findings` comes from its `findings_json` and `brief` from its `brief_md`, so findings folded in while waiting count. On decline and on needs-human, call `set_investigated(fp, False)` for every `_lock_fingerprints(req)`. On approve, append `recovered_note(rt.store, req.findings)` to `brief` before the agent runs.

- [ ] **Step 1: Write the failing tests.** Copy the `rt` fixture and `_stub_agent` from `tests/test_durable_approvals.py`. Set `rt.dry_run = False` in tests that need the gate, and monkeypatch `heim.pipelines.investigate._await_approval`. Capture `user_prompt` in the stub agent.
  - `test_approval_text_leads_with_the_headline`
  - `test_request_from_dispatch_keeps_group_findings_and_headline`: two findings and a headline survive; an old-style item still gives one synthesised finding.
  - `test_extend_pending_investigation_merges_and_rebuilds_the_brief`: on a pending row it returns `True`, the row has two findings and `brief_md` names both monitors; on a `running` row it returns `False` and changes nothing.
  - `test_a_declined_group_unlocks_every_incident`:
    - seed incidents A, B and C with `investigated=True`;
    - the request carries A and B;
    - the stubbed `_await_approval` calls `extend_pending_investigation(…, [C])`, then returns `(False, "test")`.

    A, B and C are all `investigated=False`.
  - `test_an_approved_run_sees_findings_folded_in_while_waiting`: the stub extends with C, then returns `(True, "test")`, and the captured prompt contains C's monitor name.
  - `test_the_brief_notes_checks_that_recovered_before_approval`: incident A is resolved before approval, and the captured prompt contains `"these checks have recovered: n8n"`.
  - `test_old_investigations_behave_as_before`: a request without fingerprinted findings, declined, gives `set_investigated` called only for `req.fingerprint`.
- [ ] **Step 2: Run the tests.** `.venv/bin/pytest tests/test_uptime_investigation.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement the interfaces above.** Keep `request_from_investigation` and re-arming unchanged; stored findings now carry fingerprints and round-trip as JSON.
- [ ] **Step 4: Run the tests.** `.venv/bin/pytest tests/test_uptime_investigation.py tests/test_durable_approvals.py tests/test_tracking.py tests/test_jobs.py -q`. Expected: PASS.
- [ ] **Step 5: Commit**

```bash
git add src/heim/pipelines/investigate.py tests/test_uptime_investigation.py
git commit -m "investigate: group findings, fold into a pending run, unlock the whole group"
```

### Task 6: The uptime half of the poll, and its configuration

**Files:**
- Create: `src/heim/pipelines/uptime.py`
- Modify:
  - `src/heim/pipelines/poller.py`: `_RECORDABLE`, and `run_poll` gets a third independent half
  - `src/heim/config.py`: `UptimeKumaCfg`, and `Settings.uptime_kuma`
  - `config/settings.example.yaml`: an `uptime_kuma:` block after `threshold_consecutive`
  - `.env.example`: `HEIM_UPTIME_KUMA_URL=` in the identity block and `UPTIME_KUMA=` in the secrets block, each with a one-line comment
  - `config/hosts/homelab.yaml`: add `availability` to `investigable`
  - `src/heim/dashboard/app.py`: add `"uptime"` to `_TRIGGERS`
- Test: `tests/test_uptime_pipeline.py`

**Interfaces:**
- Consumes:
  - Task 1's `parse_metrics`, `map_host`, `target_of` and `is_uptime_row`
  - Task 3's `decide`, `UptimeContext` and `UptimeDecision`
  - Task 2's store methods
  - Task 5's `extend_pending_investigation`, and `dispatch_all` with item keys `findings` and `headline`
- Produces:
  - `class UptimeKumaCfg(BaseModel): url: str = ""`, and `Settings.uptime_kuma: UptimeKumaCfg = UptimeKumaCfg()`
  - `async def fetch_metrics(url: str, api_key: str | None, *, transport: httpx.AsyncBaseTransport | None = None) -> str | None`: GET `{url}/metrics` with basic auth `("", key)` when a key is set, timeout 15 s. It returns the body on 200 and `None` on anything else, logging one warning.
  - `def pending_uptime_investigations(store) -> dict[str, int]`: host → id of the newest `pending_approval` investigation with trigger `uptime`.
  - `def build_context(cfg, suppressed: set[str], pending: dict[str, int]) -> UptimeContext`. `kuma_host` is the `map_host` of the URL's address, or the address itself.
  - `async def run_uptime(rt: Runtime, run_at: str, *, dispatch_concurrently: bool) -> dict`, returning `uptime_monitors, uptime_upserts, uptime_groups, uptime_dispatches, uptime_messages, uptime_state_changed, uptime_unreachable`
  - `_RECORDABLE` gains `"uptime_upserts", "uptime_dispatches", "uptime_messages", "uptime_state_changed"`
- Apply order in `run_uptime`, when not dry-run:
  1. Save the state writes and clears, and the fail counter.
  2. Upsert the rows.
  3. For each group:
     - a pending investigation → `extend_pending_investigation`, then `rt.notify(headline)`;
     - investigable → `dispatch_all([item], trigger="uptime")`, with `item = {**group.rows[0], "hostRole": host_role_for(...), "sshHost": ssh_host_for(...), "findings": group.findings, "headline": group.headline}`;
     - otherwise → `rt.notify(headline)`.
  4. Send the `messages` through `rt.notify`.
  5. Emit the Loki events, and emit `compute_state(..., trigger="uptime")` when `state_changed`.
- **In dry-run:** log every group headline and message as `DRY-RUN uptime: …`, return the counters, and write nothing.
- **Settings block** (copy):

  ```yaml
  # Uptime Kuma as an alert source: every unpaused monitor is expected up (empty url = off).
  # The API key (Uptime Kuma → Settings → API Keys) goes in .env as UPTIME_KUMA.
  uptime_kuma:
    url: "${HEIM_UPTIME_KUMA_URL:-}"
  ```

- [ ] **Step 1: Write the failing tests.**
  - Fixture: copy the `rt` fixture from `tests/test_thresholds.py`, with `dry_run=False`. Before `load_config`, set `HEIM_UPTIME_KUMA_URL=http://10.0.0.3:3001` and `UPTIME_KUMA=test-key`.
  - Capture `rt.notify` with a list and monkeypatch `uptime.dispatch_all`. Feed `/metrics` text by monkeypatching `uptime.fetch_metrics`.
  - Tests:
    - `test_settings_ship_uptime_kuma_off`: with the env var unset, `load_config(...).settings.uptime_kuma.url == ""`, and `run_poll` never calls `fetch_metrics`.
    - `test_two_down_monitors_dispatch_one_grouped_investigation`: one `dispatch_all` call with trigger `"uptime"`, a single item with `len(item["findings"]) == 2` and `item["headline"].startswith("🔴 Down on ubuntu-server: ")`. Two `[uptime]` rows are open.
    - `test_report_only_hosts_notify_instead`: a monitor on `10.0.0.24` gives no dispatch and one notify ending in `"(report only: not a HEIM host)"`.
    - `test_dry_run_writes_nothing`: with `rt.dry_run = True` and a down monitor, `open_rows() == []`, `uptime_states() == {}`, `uptime_fail_polls() == 0`, and no notify or dispatch.
    - `test_unreachable_alerts_after_two_polls_and_never_resolves`: seed an open `[uptime]` row; `fetch_metrics` returns `None` on three polls. Exactly one notify equals the unreachable copy, and the seeded row is still open.
    - `test_new_downs_join_a_pending_uptime_investigation`:
      - seed `create_investigation(host="ubuntu-server", trigger="uptime", status="pending_approval", findings_json="[]", brief_md="x")`;
      - a new down monitor arrives.

      There is no dispatch, the row's `findings_json` holds the new finding, and the notify starts with `"🔴 Also down on ubuntu-server: "`.
    - `test_the_uptime_half_failing_never_stops_the_others`: `fetch_metrics` raises; `run_poll` still returns the alert-half counters, and the error is logged.
    - `test_fetch_metrics_uses_basic_auth`: with an `httpx.MockTransport`, the request header `Authorization` equals `"Basic " + b64encode(b":test-key")`. A 200 response gives its body, and a 401 gives `None`.
    - `test_homelab_investigates_availability`: `"availability" in load_config(...).hosts["homelab"].investigable`.
- [ ] **Step 2: Run the tests.** `.venv/bin/pytest tests/test_uptime_pipeline.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement the interfaces, apply order, config and copy above.** In `run_poll`, run the half only when `cfg.settings.uptime_kuma.url` is set, inside its own `try/except` that logs `"the uptime half of the poll failed"`.
- [ ] **Step 4: Run the tests.** `.venv/bin/pytest -q`. Expected: everything passes except the known local-settings failure.
- [ ] **Step 5: Commit**

```bash
git add src/heim/pipelines/uptime.py src/heim/pipelines/poller.py src/heim/config.py config/settings.example.yaml .env.example config/hosts/homelab.yaml src/heim/dashboard/app.py tests/test_uptime_pipeline.py
git commit -m "poller: Uptime Kuma as a third poll half (grouped prompts, report-only, unreachable)"
```

### Task 7: The daily run leaves `[uptime]` incidents alone

**Files:**
- Modify: `src/heim/pipelines/daily.py:137` (`open_rows = …`)
- Test: `tests/test_uptime_pipeline.py`

**Interfaces:**
- Consumes: Task 1's `is_uptime_row`.
- Produces: `run_daily` passes `reconcile()` only the open rows that are not uptime rows.

- [ ] **Step 1: Write the failing test** `test_daily_run_leaves_uptime_incidents_alone`. Follow the `run_daily` fakes in `tests/test_tracking.py::test_daily_records_the_run_and_its_findings`, with an analysis that has **no** findings. Seed an open `[uptime]` row with `missedRuns=1`, run `daily.run_daily` twice, and assert the row is still `open` with `missedRuns == 1`.
- [ ] **Step 2: Run it.** `.venv/bin/pytest tests/test_uptime_pipeline.py -q -k daily`. Expected: FAIL (the row is resolved).
- [ ] **Step 3: Filter with `is_uptime_row`** at the `open_rows` read that feeds `reconcile` (the later `compute_state` call keeps every row).
- [ ] **Step 4: Run it.** Same command, then `.venv/bin/pytest -q tests/test_tracking.py tests/test_reconcile.py`. Expected: PASS.
- [ ] **Step 5: Commit**

```bash
git add src/heim/pipelines/daily.py tests/test_uptime_pipeline.py
git commit -m "daily: never miss-count or resolve [uptime] incidents"
```

### Task 8: `heim check`, and the docs

**Files:**
- Modify:
  - `src/heim/pipelines/uptime.py`: add `check_lines`
  - `src/heim/cli.py`: `_cmd_check`, after the Home Assistant block
  - `README.md`: the configuration reference, and a short "Uptime Kuma" paragraph in the observability section
  - `AGENTS.md`: §1 feature table (Detection row), §2 invariant 3 (add `[uptime]`), §3 integrations table
- Test: `tests/test_uptime_pipeline.py`

**Interfaces:**
- Consumes: Task 1's `parse_metrics` and `unmapped_monitors`, and Task 6's `fetch_metrics`.
- Produces: `def check_lines(text: str | None, cfg) -> list[tuple[bool | None, str, str]]`, consumed by `_cmd_check`'s `line(...)`.
  - `None` or an empty parse gives `[(False, "uptime kuma", "unreachable, or no monitors in /metrics (check UPTIME_KUMA)")]`.
  - Otherwise, `(True, "uptime kuma", f"{n} active monitors")`, followed when there are unmapped monitors by `(None, "uptime kuma", f"{k} monitor(s) map to no HEIM host (report only): {names}")`.
  - When `uptime_kuma.url` is empty, `_cmd_check` prints nothing for it.

- [ ] **Step 1: Write the failing test** `test_check_lines_reports_monitors_and_report_only_targets`. With text holding monitors on `10.0.0.10` and `10.0.0.24`, it gives `[(True, "uptime kuma", "2 active monitors"), (None, "uptime kuma", "1 monitor(s) map to no HEIM host (report only): k8s-w1")]`. Also assert that `check_lines(None, cfg)` returns a single `False` line.
- [ ] **Step 2: Run it.** `.venv/bin/pytest tests/test_uptime_pipeline.py -q -k check_lines`. Expected: FAIL.
- [ ] **Step 3: Implement `check_lines`, and call it from `_cmd_check`** (`await fetch_metrics(url, env("UPTIME_KUMA"))`). Update the docs:
  - **README:** what the source does, the two `.env` names, what is report-only, how to mute a monitor (the dashboard's mute), and that the daily email doesn't list `[uptime]` incidents.
  - **AGENTS.md invariant 3:** "the poller resolves only `[alert] `, threshold detection only `[metric] `, the Uptime Kuma half only `[uptime] `".
  - **AGENTS.md §3 row:** `| Uptime Kuma | read (/metrics) | pipelines/uptime, incidents/uptime_logic | API key (basic auth) |`.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: everything passes except the known local-settings failure.
- [ ] **Step 5: Commit**

```bash
git add src/heim/pipelines/uptime.py src/heim/cli.py README.md AGENTS.md tests/test_uptime_pipeline.py
git commit -m "uptime: heim check reports Uptime Kuma; document the source"
```
