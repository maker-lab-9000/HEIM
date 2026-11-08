# Tooling feedback → GitHub issues Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agents' tooling suggestions become comments on one open GitHub issue per tool, filed by the daemon; agents can read those issues through a read-only `github_issues` tool.

**Architecture:** Pipelines write suggestions to a `feedback_outbox` table (never call GitHub). The daemon's poll cycle drains the outbox through a small write-scoped GitHub channel, tracking one issue per target in `feedback_issues`. A GET-only tool with a separate read token lets the agent see open issues.

**Tech Stack:** Python 3, httpx (tests use `httpx.MockTransport`), SQLite store, Jinja prompts, FastAPI dashboard.

**Spec:** `docs/superpowers/specs/2026-11-08-tooling-feedback-issues-design.md`

## Global Constraints

- Agents never write to GitHub; the `github_issues` tool is GET-only, fixed to `https://api.github.com/repos/<repo>/issues…`, label `heim-feedback`, token `HEIM_GITHUB_READ_TOKEN`.
- Poster uses `HEIM_GITHUB_TOKEN`; repo is `settings.github.repo`, default `os.environ["HEIM_GITHUB_REPO"]` (empty = off).
- Labels: `heim-feedback` and `tool:<target>`. Title: `Tooling feedback: <target>`. Targets: a tool name in `cfg.tools`, `security_audit`, or `general`.
- `tool: covered by #N` lines (nothing else) are stored as feedback, never queued.
- Every outgoing body passes `scrub()`; the replacement text is `‹redacted›`.
- Outbox row stops retrying after `MAX_ATTEMPTS = 10`. Drain at most `DRAIN_BATCH = 5` rows per poll cycle.
- Nothing is queued on `rt.dry_run` or from `heim replay`.
- GitHub failures never raise into a pipeline or the poll cycle, and never delay the dead-man ping (drain runs after it).
- design.md: lamps with words, no emoji; CSS ≤ 36,864 bytes. Golden modules untouched. No real repo name, token or IP in the tree.

## Review Focus

1. A GitHub issue stored as open but closed by the operator → next row opens a new issue (Task 3 test `test_closed_issue_opens_a_new_one`).
2. Bad token / 401 / network error → row keeps `attempts+1`, `error`, nothing raises, later rows still tried (Task 3 `test_failure_is_recorded_and_retried`).
3. A suggestion containing a LAN IP or the SSH user → never leaves unscrubbed, even when it was queued before the env changed (Task 2 `test_scrub_*`, Task 3 `test_poster_scrubs_at_send_time`).
4. Feature unconfigured (no repo or no token) → no outbox rows, tool not offered, prompt line absent (Tasks 4 and 5).
5. Model writes a tool name that doesn't exist (`ssh: …`) → target `general`, not a new per-name issue (Task 4 `test_unknown_tool_goes_to_general`).

---

### Task 1: Settings and store

**Files:**
- Modify: `src/heim/config.py` (new `GitHubCfg`, `Settings.github`)
- Modify: `src/heim/incidents/store.py` (two tables, methods, prune)
- Test: `tests/test_feedback_issues_store.py`

**Interfaces:**
- Produces:
  - `GitHubCfg(repo: str)` with `read_token() -> str` (`HEIM_GITHUB_READ_TOKEN`), `write_token() -> str` (`HEIM_GITHUB_TOKEN`), `can_read -> bool` (repo and read token), `can_write -> bool` (repo and write token). `Settings.github: GitHubCfg = GitHubCfg()`.
  - `Store.queue_feedback(target: str, investigation_id: int, body: str, created_at: str = "") -> int`
  - `Store.pending_feedback(limit: int, max_attempts: int) -> list[dict]` (unposted, `attempts < max_attempts`, oldest first)
  - `Store.mark_feedback_posted(row_id: int, posted_at: str, issue_number: int) -> None`
  - `Store.mark_feedback_failed(row_id: int, error: str) -> None` (attempts += 1)
  - `Store.feedback_issue(target: str) -> dict | None` / `Store.set_feedback_issue(target, number, state, url, comments, updated_at) -> None`
  - `Store.feedback_issues() -> dict[str, dict]`, `Store.outbox_rows(target: str | None = None) -> list[dict]` (unposted rows, for the dashboard)
  - Tables `feedback_outbox(id, target, investigation_id, body, created_at, posted_at, issue_number, attempts, error)` and `feedback_issues(target PK, number, state, url, comments, updated_at)`.

- [ ] **Step 1: Failing tests** — `test_github_cfg_reads_env` (repo from `HEIM_GITHUB_REPO`, `can_read`/`can_write` each need their own token), `test_outbox_roundtrip` (queue two, `pending_feedback(5, 10)` oldest first; posted row disappears; failed row has `attempts == 1` and `error`; row with `attempts == 10` excluded), `test_feedback_issue_upsert`, `test_prune_drops_posted_outbox_rows_only` (posted older than retention gone; unposted kept regardless of age).
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_feedback_issues_store.py -q` — Expected: FAIL (no `GitHubCfg` / `queue_feedback`).
- [ ] **Step 3: Implement.** `GitHubCfg.repo` default via `Field(default_factory=…)` like `UptimeKumaCfg`. Tables in the `CREATE … IF NOT EXISTS` script; prune `feedback_outbox WHERE posted_at != '' AND posted_at < cutoff`.
- [ ] **Step 4: Run** same command — Expected: PASS; then full suite.
- [ ] **Step 5: Commit** `feat(store): feedback outbox and per-tool issue rows`.

### Task 2: Pure helpers and the GitHub channel

**Files:**
- Create: `src/heim/feedback_issues.py` (pure)
- Create: `src/heim/channels/github.py` (I/O)
- Test: `tests/test_feedback_issues.py`

**Interfaces:**
- Produces (`heim.feedback_issues`):
  - `LABEL = "heim-feedback"`, `REDACTED = "‹redacted›"`, `MAX_ATTEMPTS = 10`, `DRAIN_BATCH = 5`
  - `target_for(tool: str, known: Iterable[str]) -> str` (`tool` if known else `"general"`)
  - `is_covered_only(suggestion: str) -> bool` — matches `^(already )?covered by #\d+\.?$` case-insensitively
  - `identity_values(env_example: Path, environ: Mapping[str, str]) -> list[str]` — names from `.env.example` lines `NAME=…`, values from `environ`, non-empty, length ≥ 4, longest first
  - `scrub(text: str, secrets: list[str]) -> str` — IPv4, IPv6 (`[0-9a-f]*:[0-9a-f:]{2,}` with ≥ 2 colons and a hex group), each secret → `REDACTED`
  - `issue_title(target) -> str`, `issue_labels(target) -> list[str]`, `comment_body(suggestion, source) -> str` (suggestion, blank line, `_source: {source}_`)
- Produces (`heim.channels.github`):
  - `class GitHub(repo: str, token: str, transport: httpx.AsyncBaseTransport | None = None)` with async `get_issue(number) -> dict`, `create_issue(title, body, labels) -> dict`, `comment(number, body) -> dict`. Base URL `https://api.github.com/repos/{repo}`, headers `Authorization: Bearer`, `Accept: application/vnd.github+json`, timeout 15 s; non-2xx raises `httpx.HTTPStatusError`.

- [ ] **Step 1: Failing tests** — `test_scrub_ipv4_ipv6_and_identity` (`"ssh 192.168.1.20 as svcuser fe80::1"` with secrets `["svcuser"]` → no `192.168`, no `svcuser`, no `fe80::1`, three `‹redacted›`); `test_scrub_keeps_tool_text` (`"add --since flag to journalctl"` unchanged; `"12:30"` unchanged); `test_identity_values_from_env_example(tmp_path)`; `test_covered_only` (`"covered by #42"`, `"Already covered by #7."` true; `"covered by #42, plus add X"` false); `test_target_for`; `test_github_client_paths` (MockTransport records `POST /repos/o/r/issues` with labels, `POST …/issues/42/comments`, `GET …/issues/42`, bearer header present).
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_feedback_issues.py -q` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement** both modules.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat: GitHub issue channel and feedback scrub`.

### Task 3: The drain, run by the daemon

**Files:**
- Create: `src/heim/pipelines/feedback_issues.py`
- Modify: `src/heim/daemon.py` (`_poll_job`: after `deadman.ping`, `await _drain_feedback(rt)`)
- Test: `tests/test_feedback_drain.py`

**Interfaces:**
- Consumes: Task 1 store methods, Task 2 helpers and `GitHub`.
- Produces: `async def drain_outbox(rt: Runtime, client: GitHub | None = None) -> dict` returning `{"posted": n, "failed": m}`; no-op `{}` when `not rt.config.settings.github.can_write` or `rt.dry_run`. `daemon._drain_feedback(rt)` wraps it in `try/except Exception: log.exception`.

Per row: secrets = `identity_values(cfg.root.parent / ".env.example", os.environ)`; body = `scrub(row.body, secrets)`. If `feedback_issue(target)` exists → `get_issue`; state `open` → `comment`, else create. No stored issue → `create_issue(issue_title, body, issue_labels)`. After success `set_feedback_issue(...)` from the response (`number`, `state`, `html_url`, `comments`) and `mark_feedback_posted`. Any exception → `mark_feedback_failed(row.id, f"{type(e).__name__}: {e}"[:300])`, continue to the next row.

- [ ] **Step 1: Failing tests** (use the `rt` fixture from `test_tracking`, `monkeypatch.setenv` repo + write token, MockTransport client): `test_first_row_opens_issue_then_comments` (two rows same target → one `POST /issues`, one `POST /issues/N/comments`); `test_closed_issue_opens_a_new_one`; `test_failure_is_recorded_and_retried` (401 on first row → `attempts 1`, second row still posted; next drain retries the first); `test_poster_scrubs_at_send_time` (row queued with an IP, then `HEIM_SSH_USER` set in env and present in body → sent body has neither); `test_drain_off_without_token_or_in_dry_run`; `test_poll_job_drains_after_the_ping` (monkeypatch `deadman.ping` and `drain_outbox` to append to one list → order `["ping", "drain"]`; a raising drain does not raise out of `_poll_job`).
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_feedback_drain.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS; full suite.
- [ ] **Step 5: Commit** `feat(daemon): drain tooling feedback to GitHub issues`.

### Task 4: Queue from the pipelines

**Files:**
- Modify: `src/heim/pipelines/investigate.py` (`record_tool_feedback`)
- Modify: `src/heim/pipelines/security_audit.py` (also queue `## Audit feedback`)
- Modify: `src/heim/pipelines/replay.py` (pass `file_issues=False`)
- Test: `tests/test_feedback_queueing.py`

**Interfaces:**
- Produces: `record_tool_feedback(rt, investigation_id, report_md, *, file_issues: bool | None = None) -> int` — `None` means `not rt.dry_run`; queues only when that is true **and** `settings.github.can_write`. Source string: `f"investigation #{id} · {model} · {date}"` (model from the investigation row; date = first 10 chars of `rt.now_iso()`).
- `queue_audit_feedback(rt, investigation_id: int, report_md: str) -> int` in `security_audit.py`: `extract_audit_feedback`; non-empty `improve`/`check` parts joined under `### Improve the audit` / `### What else to check` into ONE row, target `security_audit`; skipped when both parts are empty or only `- nothing this week`.

- [ ] **Step 1: Failing tests** — `test_suggestions_are_queued_per_target` (two lines for `loki_query`, one for `ssh_diagnostic` → three rows, targets right); `test_covered_line_is_stored_not_queued`; `test_unknown_tool_goes_to_general`; `test_nothing_queued_without_write_config`; `test_dry_run_and_replay_queue_nothing`; `test_audit_feedback_becomes_one_row`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_feedback_queueing.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.** Feedback is still stored in `tool_feedback` exactly as before for every case (the Tools page keeps working with GitHub off).
- [ ] **Step 4: Run** — Expected: PASS; full suite.
- [ ] **Step 5: Commit** `feat(pipelines): queue tooling and audit feedback for GitHub`.

### Task 5: The read-only `github_issues` tool and the prompts

**Files:**
- Create: `config/tools/github_issues.yaml`, `src/heim/tools/github_issues.py`
- Modify: `src/heim/tools/base.py` (`load_tools` skips a tool whose class `available(config) -> False`)
- Modify: `config/agents/investigator.yaml`, `config/agents/security_auditor.yaml` (add the tool)
- Modify: `config/prompts/investigator.md.j2`, `config/prompts/security_auditor.md.j2`, `investigate.build_system_prompt`, `security_audit.build_audit_system_prompt` (pass `github_issues: bool`)
- Modify: `src/heim/dashboard/app.py` `TOOL_GUARDS` (one line describing the guard)
- Test: `tests/test_github_issues_tool.py`

**Interfaces:**
- Consumes: `GitHubCfg.can_read`, `read_token()`, `LABEL`.
- Produces: `GitHubIssuesTool(Tool)` with `@classmethod available(cls, config) -> bool` (= `can_read`). Args: `tool` (string, optional → label `tool:<tool>`), `state` (`open`|`closed`, default `open`), `number` (integer, optional). Lists: `GET /repos/{repo}/issues?labels=heim-feedback[,tool:x]&state=…&per_page=20` → `[{number, title, state, labels, updated_at}]` (pull requests filtered out). `number` → the issue plus `GET …/comments?per_page=100`, last 5, each clipped to 1,000 chars; whole result through `clip(…, 8192)`. Any other method or path is impossible by construction (no free-form URL argument).
- Prompt line (only when `github_issues` is true), appended to the `## Tooling feedback` rule in both prompts: "Before writing it you MAY call github_issues to see what is already filed. Skip a suggestion that is already there, write 'tool_name: covered by #N' if you want to confirm it, or add new detail in a normal line."

- [ ] **Step 1: Failing tests** — `test_lists_feedback_issues_for_a_tool` (request has `labels=heim-feedback,tool:loki_query`, bearer is the READ token, PRs dropped); `test_reads_one_issue_with_last_comments`; `test_rejects_bad_state` (`state="all"` → error JSON, no request); `test_not_offered_without_read_config` (`load_tools(["loki_query","github_issues"], …)` returns only `loki_query`); `test_prompt_mentions_tool_only_when_configured` (investigator and auditor system prompts).
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_github_issues_tool.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS. Full suite: tests pinned to the exact tool list (activity map, tools pages, prompt name lists) are updated to include `github_issues`, nothing else.
- [ ] **Step 5: Commit** `feat(tools): read-only github_issues tool for the agents`.

### Task 6: Dashboard

**Files:**
- Modify: `src/heim/dashboard/app.py` (`tool_detail`, `/tools` list context)
- Modify: `src/heim/dashboard/templates/tool.html`, `tools.html`; `heim.css` only if needed
- Test: `tests/test_tools_pages.py` (extend)

**Interfaces:**
- Consumes: `Store.feedback_issues()`, `Store.outbox_rows(target)`.
- Produces: tool page shows `Issue #42 · open · 7 comments` linked to `url` (rel="noopener"), and per waiting row a lamp + `Waiting` (attempts 0) / `Retrying` (0 < attempts < 10) / `Failed` (≥ 10) with the error clipped; `/tools` shows `Issue #42` beside the tool. `/tools/security_audit` is not a page — the security issue appears on `/security` next to the Audit feedback panel as the same one-line link.

- [ ] **Step 1: Failing tests** — `test_tool_page_links_its_issue`, `test_tool_page_shows_waiting_and_failed_rows`, `test_tools_list_shows_issue_number`, `test_security_page_links_audit_issue`, `test_no_issue_line_when_none`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_tools_pages.py -q` — Expected: new tests FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS; full suite including the CSS cap test.
- [ ] **Step 5: Commit** `feat(dashboard): show each tool's feedback issue`.

### Task 7: Config examples and docs

**Files:**
- Modify: `config/settings.example.yaml`, `config/settings.yaml` is gitignored — leave it; `.env.example` (`HEIM_GITHUB_REPO=`, `HEIM_GITHUB_READ_TOKEN=`, `HEIM_GITHUB_TOKEN=` with one comment each on the token's scope: fine-grained, that repo only, Issues read / read+write)
- Modify: `AGENTS.md` (§1 feature rows Agent/Tools, §3 integrations row "GitHub", §5.6 tooling-feedback paragraph, test count), `docs/AGENTS-AND-TOOLS.md`, `docs/CONFIGURATION.md`, `docs/OPERATIONS.md` ("Tooling feedback issues": tokens, where failures show, how to turn off)
- Test: existing `test_both_settings_yamls_document_the_new_knobs`-style check — add `github` to the example only

- [ ] **Step 1:** Add `github: {repo: "${HEIM_GITHUB_REPO:-}"}` commented block to the example settings; update docs.
- [ ] **Step 2: Run** full suite `.venv/bin/pytest -q` — Expected: all pass except the known local-settings failure.
- [ ] **Step 3: Commit** `docs: tooling feedback issues`.
