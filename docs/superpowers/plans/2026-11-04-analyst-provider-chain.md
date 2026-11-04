# Daily Analyst Provider Chain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The daily analyst tries an ordered chain of models (Anthropic → OpenRouter DeepSeek → later llama.cpp), the chain can be overridden from the dashboard, fallbacks are visible in the email/Telegram/dashboard, and an all-fail run emails the operator.

**Architecture:** `config.py` gains a `chain` on the analyst and an `openai_compat` provider; `llm.run_chain` walks the chain and returns every attempt. A pure `model_chain.resolve_chain` layers a store-held override (new `model_overrides` table, written only by the dashboard through the action allow-list) over the YAML chain, validated against `settings.analyst_models`. `pipelines/daily.py` uses both, and adds the fallback banner/subject tag and the failure email from a new pure renderer.

**Tech Stack:** Python 3, pydantic, httpx, anthropic SDK, SQLite, FastAPI + Jinja + htmx, pytest (async tests run without decorators, as in the existing suite).

**Spec:** `docs/superpowers/specs/2026-11-04-analyst-provider-chain-design.md`

## Global Constraints

- Shipped default chain, in order: `anthropic` / `claude-opus-5-5`, then `openrouter` / `deepseek/deepseek-v4.1-flash-1017`. llama.cpp only as a commented example (`provider: openai_compat`, `base_url: ${HEIM_LLAMACPP_URL:-}`).
- Providers: `anthropic | openrouter | openai_compat`. No OpenAI-the-API anywhere.
- Golden files NOT edited: `src/heim/reports/daily_dashboard.py`, `src/heim/incidents/reconcile.py`, `src/heim/incidents/poller_logic.py`. `src/heim/llm.py` IS changed deliberately: add a dated (2026-11-04) docstring note that primary+fallback became an ordered chain.
- Old `daily_analyst.yaml` with `primary`/`fallback` must still load; `chain` + `primary` together is a config error; an empty chain is a config error.
- "Fallback" = the answering entry is not index 0 of the chain *in effect for that run*. An active override is never itself flagged (only the "override — set <time>" note on `/agents/daily`).
- Dashboard writes only via `_ACTION_HELPERS`; new helpers `set_model_override`, `clear_model_override`. Overrides never expire.
- Side channels (Telegram, failure email) are fire-and-forget: log and swallow, then re-raise the original `AnalystChainFailed`.
- Read `design.md` before touching any template. No secrets or real URLs in the tree.
- `.venv/bin/pytest -q` green at every commit (baseline 1305 tests).

## Review Focus

1. An override naming an entry since removed from `settings.analyst_models` → the run uses the YAML chain, logs a WARNING, and `/agents/daily` says the override is stale (Task 4 test, Task 6 test).
2. A chain entry whose API key env var is unset (e.g. no `OPENROUTER_API_KEY`) → that attempt fails with an error naming the variable, and the next entry is tried (Task 2 test).
3. Anthropic answers with `stop_reason="max_tokens"` and truncated JSON → counted as a failed attempt (unparseable) with its billed tokens kept, next entry tried (Task 2 test).
4. Dashboard POST with a gap (`slot_1` empty, `slot_2` set), a duplicate entry, no entries, or an unknown key → 400 and nothing stored (Task 6 tests).
5. All entries fail AND the email send itself raises → the run still raises `AnalystChainFailed` (not the SMTP error), and the daemon heartbeat records every attempt (Task 5 test).

---

### Task 1: Config — the chain, the `openai_compat` provider, the allow-list

**Files:**
- Modify: `src/heim/config.py` (`ModelRef` ~L268, `AnalystCfg` ~L284, `Settings` ~L137-181)
- Modify: `config/agents/daily_analyst.yaml`, `config/settings.example.yaml` (next to `investigator_models`, ~L99)
- Test: `tests/test_analyst_chain.py` (new)

**Interfaces:**
- Produces:
  - `ModelRef(provider: Literal["anthropic","openrouter","openai_compat"]="anthropic", model: str, base_url: str = "", api_key_env: str = "")`; validator: `openai_compat` requires non-empty `base_url`. Property `ModelRef.key -> str` = `f"{provider}|{model}"`, plus `f"|{base_url}"` when `base_url` is set. Property `ModelRef.label -> str` = `model` (used in subjects/Telegram).
  - `AnalystCfg.chain: list[ModelRef]` — always populated after validation. `primary`/`fallback` stay as optional input fields (`ModelRef | None = None`); a `model_validator(mode="after")` builds `chain = [primary] + ([fallback] if fallback else [])` when `chain` is empty, raises `ValueError` when both `chain` and `primary` are given or the result is empty.
  - `Settings.analyst_models: list[ModelRef] = []`.

- [ ] **Step 1: Write the failing tests** in `tests/test_analyst_chain.py`:

```python
def test_chain_loads_in_order():
    cfg = AnalystCfg(chain=[{"provider": "anthropic", "model": "claude-opus-5-5"},
                            {"provider": "openrouter", "model": "deepseek/deepseek-v4.1-flash-1017"}])
    assert [r.key for r in cfg.chain] == ["anthropic|claude-opus-5-5",
                                         "openrouter|deepseek/deepseek-v4.1-flash-1017"]

def test_primary_fallback_still_loads_as_a_chain():
    cfg = AnalystCfg(primary={"provider": "openrouter", "model": "a/b"},
                     fallback={"provider": "anthropic", "model": "claude-opus-5-5"})
    assert [r.model for r in cfg.chain] == ["a/b", "claude-opus-5-5"]

def test_chain_and_primary_together_is_an_error():  # pytest.raises(ValidationError)
def test_empty_chain_is_an_error():                 # AnalystCfg(chain=[]) raises
def test_openai_compat_needs_a_base_url():           # ModelRef(provider="openai_compat", model="m") raises
def test_key_includes_base_url_only_when_set():
    assert ModelRef(provider="openai_compat", model="local", base_url="http://x:8080/v1").key \
        == "openai_compat|local|http://x:8080/v1"

def test_shipped_daily_analyst_yaml_is_anthropic_then_deepseek():
    cfg = load_config()  # repo config; use the existing conftest identity env
    assert [r.key for r in cfg.analyst.chain] == ["anthropic|claude-opus-5-5",
                                                 "openrouter|deepseek/deepseek-v4.1-flash-1017"]
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_analyst_chain.py -v` — expected: FAIL (no `chain` attribute).
- [ ] **Step 3: Implement** the `ModelRef` / `AnalystCfg` / `Settings` changes above. Rewrite `config/agents/daily_analyst.yaml` to the `chain:` form from spec §1 (keep `max_tokens: 8192`, `prompt: analyst.md`, the Opus-thinking comment, and the commented llama.cpp entry). In `settings.example.yaml` add a commented `analyst_models:` block (Anthropic Opus, DeepSeek Flash, commented llama.cpp) explaining it is the dashboard's allow-list and that every entry should have a `model_prices` row, plus `analyst_models: []`.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_analyst_chain.py tests/test_observability.py -v` — PASS (the existing observability tests still construct `AnalystCfg(primary=…, fallback=…)`).
- [ ] **Step 5: Commit** `feat(config): analyst model chain + openai_compat provider`

---

### Task 2: `llm.run_chain` — walk the chain, record every attempt

**Files:**
- Modify: `src/heim/llm.py`
- Test: `tests/test_analyst_chain.py`

**Interfaces:**
- Consumes: `ModelRef`, `AnalystCfg` (Task 1).
- Produces:
  - `@dataclass Attempt(provider: str, model: str, ok: bool, error: str = "", input_tokens: int = 0, output_tokens: int = 0)`, with `as_dict() -> dict`. Every attempt that got a response carries its usage — the successful one included — so the run's cost is the sum over attempts.
  - `@dataclass ChainResult(text: str, analysis: dict | None, model_used: str, index: int, usage: dict, attempts: list[Attempt])` — `index` is the answering entry's position; `usage` is the answering entry's `{"input","output"}`.
  - `class AnalystChainFailed(RuntimeError)` with `.attempts: list[Attempt]`; `str()` is `"all N analyst models failed: 1) provider model — error; 2) …"`.
  - `async def run_chain(chain: list[ModelRef], system: str, user: str, max_tokens: int, accept: Callable[[str], dict | None] | None = None) -> ChainResult`.
  - `analyst_complete(cfg, system, user) -> tuple[str, str, dict]` kept as a thin wrapper over `run_chain(cfg.chain, …, accept=None)` (existing callers/tests).

- [ ] **Step 1: Write the failing tests** (reuse the `_FakeHttpClient` / `_FakeClient` / `_Resp` / `_Text` shapes from `tests/test_observability.py`; copy them into the new file or import them):

```python
async def test_first_entry_answers(): ...           # index == 0, len(attempts) == 1, attempts[0].ok
async def test_error_falls_through_to_next():       # anthropic raises "usage limits" → openrouter answers
    assert (res.index, res.model_used) == (1, "deepseek/deepseek-v4.1-flash-1017")
    assert [a.ok for a in res.attempts] == [False, True]
    assert "usage limits" in res.attempts[0].error
async def test_unparseable_falls_through_and_keeps_billed_tokens():
    # anthropic returns _Resp([_Text('{"overallHealth": "ok", ')], "max_tokens", (5000, 8192))
    # accept=parse_analysis
    assert res.attempts[0].ok is False and "unparseable" in res.attempts[0].error
    assert (res.attempts[0].input_tokens, res.attempts[0].output_tokens) == (5000, 8192)
    assert res.analysis["overallHealth"]
async def test_missing_key_env_fails_that_entry_only():
    # delenv OPENROUTER_API_KEY; chain [openrouter, anthropic]
    assert "OPENROUTER_API_KEY" in res.attempts[0].error and res.index == 1
async def test_all_fail_raises_with_every_attempt():
    with pytest.raises(AnalystChainFailed) as ei: ...
    assert len(ei.value.attempts) == 2
    assert "anthropic claude-opus-5-5" in str(ei.value) and "deepseek" in str(ei.value)
async def test_openai_compat_posts_to_its_base_url_without_auth_when_no_key_env():
    # capture url + headers in the fake client
    assert url == "http://llama:8080/v1/chat/completions" and "Authorization" not in headers
async def test_errors_are_clipped_to_300_chars(): ...
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_analyst_chain.py -v` — FAIL (`run_chain` undefined).
- [ ] **Step 3: Implement.** Generalise `_complete_openrouter` into `_complete_openai_compat(url: str, key: str | None, model, system, user, max_tokens) -> (text, usage)`; `openrouter` = `OPENROUTER_URL` + `OPENROUTER_API_KEY`; `openai_compat` = `base_url.rstrip("/") + "/chat/completions"` + `env(api_key_env)` if set (no `Authorization` header when there is no key). A missing required key raises `RuntimeError("OPENROUTER_API_KEY is not set")`-style text. In `run_chain`, any exception → failed `Attempt` (error = `f"{type(e).__name__}: {e}"[:300]`); when `accept` is given and returns `None` → failed `Attempt` with error `"unparseable output"` and the call's usage kept. Log one WARNING per failed attempt. Update the module docstring with the 2026-11-04 note (primary+fallback → ordered chain, unparseable now falls through, why: the Anthropic usage-limit outage).
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_analyst_chain.py tests/test_observability.py -v` — PASS.
- [ ] **Step 5: Commit** `feat(llm): run the analyst through an ordered model chain`

---

### Task 3: Store — `model_overrides` table and `runs.attempts_json`

**Files:**
- Modify: `src/heim/incidents/store.py` (schema block ~L78-235, `_ADDED_COLUMNS["runs"]`, `_RUN_COLS`, new helpers next to `set_recommendation_state` ~L1390)
- Test: `tests/test_analyst_chain.py`

**Interfaces:**
- Produces:
  - Table `model_overrides(agent TEXT PRIMARY KEY, chain_json TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL DEFAULT '')`.
  - `IncidentStore.set_model_override(agent: str, chain: list[dict], updated_by: str = "dashboard") -> None` (INSERT OR REPLACE, `updated_at = self._now()`; refuses an empty list with `ValueError`).
  - `IncidentStore.clear_model_override(agent: str) -> bool`.
  - `IncidentStore.model_override(agent: str) -> dict | None` → `{"chain": list[dict], "updated_at": str, "updated_by": str}`; a row whose JSON does not parse returns `None`.
  - `runs.attempts_json TEXT NOT NULL DEFAULT '[]'` added via `_ADDED_COLUMNS` and to `_RUN_COLS`.

- [ ] **Step 1: Write the failing tests:** round-trip set → get → clear (clear returns `True`, then `False`); set replaces the previous chain; empty chain raises; corrupt `chain_json` (written via raw SQL) reads as `None`; an old db without `attempts_json` gains it on connect (follow `test_migrations_add_the_observability_columns_to_an_old_db` in `tests/test_observability.py`); `insert_run(..., attempts_json="[...]")` persists.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_analyst_chain.py tests/test_tracking.py -v` — PASS.
- [ ] **Step 5: Commit** `feat(store): model_overrides table and runs.attempts_json`

---

### Task 4: Pure chain resolution + the two notices

**Files:**
- Create: `src/heim/model_chain.py` (pure, no I/O)
- Create: `src/heim/reports/analyst_notice.py` (pure, new — not golden)
- Test: `tests/test_analyst_chain.py`

**Interfaces:**
- Consumes: `ModelRef`, `Attempt` (Tasks 1–2), override dict shape (Task 3).
- Produces:
  - `OVERRIDE_AGENT = "daily_analyst"`.
  - `@dataclass EffectiveChain(chain: list[ModelRef], source: Literal["yaml","override"], stale: bool, updated_at: str = "")`.
  - `resolve_chain(yaml_chain: list[ModelRef], override: dict | None, allowed: list[ModelRef]) -> EffectiveChain` — the override applies only when every entry's `key` is in `{a.key for a in allowed}`; otherwise YAML with `stale=True` (and `updated_at` of the ignored override). No override → YAML, `stale=False`.
  - `fallback_subject(subject: str, model_label: str) -> str` → `f"{subject} [fallback: {model_label}]"`.
  - `fallback_banner_html(model_used: str, attempts: list[Attempt]) -> str` — one short block: "Answered by fallback model <model>. Failed first: <provider model — error>; …". Escape all text (`html.escape`).
  - `failure_email(attempts: list[Attempt], run_at: str) -> tuple[str, str]` — subject `"HEIM daily report NOT produced — all analyst models failed"`; body lists each attempt (provider, model, error) in order, the run time, and the line "Metrics were collected; the next scheduled run will retry." Escaped.
  - `fallback_telegram(model_used: str, attempts: list[Attempt]) -> str` → `"⚠️ HEIM daily: <failed entries with errors>; report by <model_used>"`.

- [ ] **Step 1: Write the failing tests:** `resolve_chain` — no override → yaml; valid override → override in its order with `updated_at`; override with one key not allowed → yaml + `stale`; empty `allowed` → any override is stale. Notices — the subject tag exact string; banner and failure email contain every failed model and error and escape `<script>`; failure email subject exact string above; Telegram line names `claude-opus-5-5` and `deepseek/deepseek-v4.1-flash-1017`.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** the two modules. Keep the HTML inline-styled and minimal (it is prepended to / sent as an email, so no stylesheet).
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat: resolve the effective analyst chain; fallback and failure notices`

---

### Task 5: Daily pipeline, daemon heartbeat, agent status

**Files:**
- Modify: `src/heim/pipelines/daily.py` (analysis step ~L114-136, `insert_run` ~L160, email ~L188, result dict ~L212)
- Modify: `src/heim/daemon.py` (`_exc_text` L73, `_daily_job` L84)
- Modify: `src/heim/agents.py` (`status_of` ~L247)
- Modify (fakes only): `tests/test_tracking.py:741`, `tests/test_jobs.py:697,746`, `tests/test_uptime_pipeline.py:362` — they patch `daily.analyst_complete`; switch them to patch `daily.run_chain` returning a `ChainResult`.
- Test: `tests/test_analyst_chain.py`, `tests/test_agents.py`

**Interfaces:**
- Consumes: `run_chain`, `ChainResult`, `AnalystChainFailed` (Task 2); store helpers (Task 3); `resolve_chain`, notices (Task 4).
- Produces: `run_daily(...)` result dict gains `"fallback": bool`, `"model_used": str`, `"failed_models": list[str]`. `status_of` maps a latest run with `ok` and `detail.get("fallback")` to `"degraded"`.

- [ ] **Step 1: Write the failing tests** (pattern: `test_uptime_pipeline.py` ~L350 — fake `_fetch_query_ranges`, `aggregate`, `dispatch_all`; `rt` with dry-run so emails land in `rt.out_dir`):
  - `test_daily_uses_the_override_chain` — store holds an allowed override `[deepseek]`; the fake `run_chain` asserts it received exactly that chain.
  - `test_stale_override_runs_yaml_chain_and_warns` (caplog WARNING).
  - `test_fallback_run_tags_subject_and_prepends_banner` — fake returns `index=1`; the written email filename/HTML contains `[fallback: deepseek` and the banner; `result["fallback"] is True`; `runs.attempts_json` has 2 entries.
  - `test_non_fallback_email_unchanged` — `index=0`: no tag, no banner.
  - `test_failed_attempt_tokens_are_priced_into_the_run` — attempt 0 has tokens on a priced model; `runs.cost` == sum of both attempts' `cost_of`.
  - `test_all_fail_sends_failure_email_and_reraises` — fake raises `AnalystChainFailed`; `pytest.raises(AnalystChainFailed)`; a file with the failure subject exists in `out_dir`; no `runs` row written.
  - `test_all_fail_when_email_send_raises_still_raises_chain_failure` — monkeypatch `rt.send_email` to raise `OSError`; still `AnalystChainFailed`.
  - In `tests/test_agents.py`: `test_ok_fallback_run_is_degraded` — runs `[{"ok": True, "detail": {"fallback": True}, …}]` → state `"degraded"`; `test_ok_run_without_fallback_is_healthy`.
  - Daemon: `test_daily_job_records_fallback_in_heartbeat` and `test_daily_job_failure_heartbeat_lists_every_attempt` (call `daemon._daily_job(rt)` with `run_daily` patched; read `rt.store` agent runs; error text contains both model ids).
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement.**
  - `daily.py`: before the analysis, `eff = resolve_chain(cfg.analyst.chain, rt.store.model_override(OVERRIDE_AGENT), cfg.settings.analyst_models)` (a store read failure → YAML chain, logged); log WARNING when `eff.stale`. Replace `analyst_complete` + `parse_analysis` with `res = await run_chain(eff.chain, system, user, cfg.analyst.max_tokens, accept=parse_analysis)`; `analysis = res.analysis`. The old "unparseable → notify + raise" branch goes away (it is now a failed attempt). On `AnalystChainFailed`: build `failure_email(...)`, `rt.send_email` inside try/except-log, then re-raise. Cost = sum of `cost_of(a.model, a.input_tokens, a.output_tokens, prices) or 0` over all attempts (the answering attempt carries its usage too — make `run_chain` record it on the ok `Attempt`). Persist `attempts_json`. When `res.index > 0`: wrap subject/html with `fallback_subject` / `fallback_banner_html(...) + html`, and `rt.notify(fallback_telegram(...))` in try/except-log.
  - `daemon.py`: `_exc_text` clip becomes 600 for `AnalystChainFailed`, 200 otherwise; `_daily_job` puts `fallback`, `model_used`, `failed_models` from the result into the heartbeat `detail`.
  - `agents.py`: in `status_of`, after the stale/failed checks, `if last.get("detail", {}).get("fallback"): return degraded`.
- [ ] **Step 4: Run** `.venv/bin/pytest -q` — all green (including the four updated fakes).
- [ ] **Step 5: Commit** `feat(daily): run the analyst chain; fallback banner, failure email, degraded status`

---

### Task 6: Dashboard — Models panel, action route, fallback tags

**Files:**
- Modify: `src/heim/dashboard/app.py` (`_ACTION_HELPERS` L162, `agent_detail` L738, new `@app.post("/actions/models")` next to `/actions/recommendation`)
- Create: `src/heim/dashboard/templates/partials/_models_panel.html`
- Modify: `src/heim/dashboard/templates/agent.html` (include the panel when `agent.key == "daily"`), `overview.html:165` and `findings.html:12` (fallback tag)
- Test: `tests/test_dashboard_models.py` (new; fixture style from `tests/test_model_choice.py` `_client`)

**Interfaces:**
- Consumes: `resolve_chain`, `OVERRIDE_AGENT` (Task 4); store helpers (Task 3); `runs.attempts_json` (Task 3/5).
- Produces: `POST /actions/models` with fields `action` ∈ `("set","reset")` and, for `set`, `slot_1..slot_N` (N = `len(settings.analyst_models)`), each `""` or an allowed `ModelRef.key`. Forms post one field per slot because `_fields` collapses repeated keys.

- [ ] **Step 1: Write the failing tests:**
  - `test_panel_shows_yaml_chain_as_default` — `/agents/daily` lists both models in order and the word `default`.
  - `test_panel_read_only_when_no_allow_list` — `analyst_models=[]`: chain shown, no `<form` posting to `/actions/models`.
  - `test_set_override_stores_chain_in_slot_order` — post `slot_1=<deepseek key>, slot_2=<anthropic key>` → `model_override("daily_analyst")["chain"]` models in that order; page now says `override` with the set time.
  - `test_reset_clears_override`.
  - `test_rejects_gap_duplicate_empty_and_unknown` — each → 400, store unchanged (parametrised: gap `slot_1="" slot_2=k`; `slot_1=k slot_2=k`; no slots; `slot_1="openrouter|evil/model"`).
  - `test_stale_override_is_labelled` — seed an override with an un-allowed key → page says it is ignored and the YAML chain is in effect.
  - `test_unpriced_entry_is_marked` — allowed model with no `model_prices` row shows `unpriced`.
  - `test_overview_marks_fallback_run` — seed a `runs` row with `attempts_json` whose first attempt failed → overview latest-run line contains `fallback`.
  - `test_action_helpers_allow_list` — `set_model_override` and `clear_model_override` are in `_ACTION_HELPERS`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_dashboard_models.py -v` — FAIL.
- [ ] **Step 3: Implement.** Read `design.md` first. The panel: ordered list of the effective chain with its source word (`default` / `override · set <time>` / `override ignored — <reason>`), then (if `analyst_models`) a `<form method="post" action="/actions/models">` of N ordered `<select name="slot_i">` (first option blank) preselected from the effective chain, a Save button (`action=set`) and Reset to default (`action=reset`), htmx-enhanced via `respond(...)` re-rendering `_models_panel.html` like the other actions. A fallback tag on overview/findings is derived in Python (parse `attempts_json`; fallback when the first attempt is not ok) with the failed entries' errors in a `title`/`<details>`, never an emoji or glyph as status.
- [ ] **Step 4: Run** `.venv/bin/pytest -q` — all green (the stylesheet-size cap test included).
- [ ] **Step 5: Commit** `feat(dashboard): set the daily analyst's model chain from /agents/daily`

---

### Task 7: Docs

**Files:**
- Modify: `AGENTS.md` (feature table "Detection"/"Ops" rows or a new "Analyst" note; §5.7 add a "✅ Analyst provider chain" bullet pointing at the spec; test count), `docs/CONFIGURATION.md` (`chain`, `openai_compat`, `analyst_models`), `README.md` only if it describes primary/fallback.

- [ ] **Step 1:** `grep -rn "primary\|fallback\|1305" AGENTS.md README.md docs/*.md` and update each hit that describes the analyst; replace `1305` with the new count from `.venv/bin/pytest -q | tail -1`.
- [ ] **Step 2: Run** `.venv/bin/pytest -q` — green.
- [ ] **Step 3: Commit** `docs: analyst provider chain`
