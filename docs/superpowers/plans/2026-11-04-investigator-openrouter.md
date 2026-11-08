# Investigator on OpenRouter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the investigator run on OpenRouter or any OpenAI-compatible model,
chosen from the dashboard (one model, no automatic fallback), and send a
Telegram line whenever an investigation fails.

**Architecture:**
- **Model identity:** `ModelRef` (from the analyst chain) becomes the single
  way to name a model. `AgentCfg` gains a provider and a `ref`.
- **Tool loop:** `run_agent` dispatches on provider. The Anthropic path stays
  untouched; a new OpenAI-compatible loop in `agent/openai_loop.py` honours
  the same contract.
- **Model choice:** the model is resolved when the agent starts, after
  approval. The order is an explicit pinned pick, then the dashboard override
  (`model_overrides`, agent `investigator`), then the YAML.

**Tech Stack:** Python 3.12, pydantic v2, httpx (MockTransport in tests),
FastAPI + Jinja + htmx, SQLite, pytest (`asyncio_mode = "auto"`).

**Spec:** `docs/superpowers/specs/2026-11-04-investigator-openrouter-design.md`

## Global Constraints

- **Anthropic path unchanged:** existing tests for it pass unmodified
  (`tests/test_replay.py`, `test_tool_feedback.py`, `test_observability.py`,
  and the security tests).
- **Same power on both loops:** same tool list, guards, `hard_step_cap` (+3
  turns of slack), forced-final text, approval gate and report salvage.
- **No automatic fallback** for the investigator.
- **Allow-list:** `settings.investigator_models: list[ModelRef]`. A plain
  string is accepted and means `{provider: anthropic, model: <string>}`.
- **Failure Telegram text:**
  `❌ Investigation #<id> (<host>) failed on <model>: <error clipped to 300> — change the model on /agents/investigator`.
  For a job that failed before any row existed:
  `❌ Investigation of <host> failed on <model>: …`. For a restart sweep, the
  error is `interrupted by daemon restart`. Fire-and-forget; skipped on
  dry-run and without Telegram (both via `rt.notify`).
- **No retry on 4xx:** the new loop retries only on connection errors, 429
  and 5xx (3 attempts, `RETRY_WAIT_S * n`).
- **Dashboard:** follows `design.md`, with no emoji in the UI. Writes go only
  through `set_model_override` / `clear_model_override`.
- **Tests stay offline:** no network calls. `pytest -q` must stay green,
  apart from the known local-settings failure
  (`test_both_settings_yamls_document_the_new_knobs`, caused by the
  gitignored `config/settings.yaml`).
- **Docs:** each task that changes behaviour updates AGENTS.md (§1 inventory,
  §3 table, §5.7 "Multi-model agent loop" → ✅, test count),
  `docs/CONFIGURATION.md`, `docs/DASHBOARD.md` and
  `docs/AGENTS-AND-TOOLS.md` in Task 6.

## Review Focus

1. **Bad tool-call arguments:** an OpenAI model returns `arguments` that
   aren't valid JSON, or that parse to a non-object. Expect an error tool
   result, the tool never runs, and the loop continues. Tested in Task 2.
2. **Several tool calls in one turn, past the cap:** a turn asks for more
   calls than the cap has room for. Expect steps beyond the cap to get the
   forced-final text and every `tool_call_id` to still be answered,
   otherwise the API rejects the next turn. Tested in Task 2.
3. **A parked approval resolves to a removed `openai_compat` model:**
   expect the row to fail with a clear reason and Telegram to fire, with no
   exception escaping `run_investigation`. Tested in Task 4.
4. **A live `settings.yaml` with string entries in `investigator_models`:**
   expect it to load, and the dropdown and `--model claude-opus-5-5` to keep
   working. Tested in Tasks 1 and 5.
5. **Empty `content` with no tool calls:** for example, `finish_reason`
   `length`. Expect `AgentResult("")` with stop_reason `max_tokens`, and
   salvage to mark the run incomplete, never complete. Tested in Task 2.

---

### Task 1: Model identity: `AgentCfg.ref`, `investigator_models` as `ModelRef`

**Files:**
- Modify: `src/heim/config.py` (AgentCfg ~L302, Settings.investigator_models ~L211)
- Modify: `src/heim/model_chain.py`
- Modify: `config/settings.example.yaml` (investigator_models comment, ~L101-106)
- Test: `tests/test_investigator_models.py` (new)

**Interfaces:**
- Produces:
  - `AgentCfg.provider: Literal["anthropic","openrouter","openai_compat"] = "anthropic"`,
    `AgentCfg.base_url: str = ""` and `AgentCfg.api_key_env: str = ""`;
  - `AgentCfg.ref -> ModelRef`;
  - `AgentCfg.with_ref(ref: ModelRef) -> AgentCfg`, a `model_copy` that sets
    provider, model, base_url and api_key_env;
  - `Settings.investigator_models: list[ModelRef]`, with a `field_validator`
    (mode before) that turns `str` into `{"provider": "anthropic", "model": s}`;
  - in `model_chain.py`: `INVESTIGATOR_AGENT = "investigator"`;
  - `find_model(choice: str, allowed: list[ModelRef]) -> ModelRef`, which
    accepts a full key, or a bare model id matching exactly one entry. It
    otherwise raises `ValueError`, whose message lists the matching keys, or
    says "not offered";
  - `resolve_model(yaml: ModelRef, override: dict | None, allowed: list[ModelRef]) -> EffectiveChain`,
    i.e. `resolve_chain([yaml], override, allowed)` with a one-entry override
    (the chain may hold only one entry; a longer one counts as stale).

- [ ] **Step 1: Write the failing tests**
  - `test_agentcfg_defaults_to_anthropic_ref`: load the repo's
    `investigator.yaml`; `cfg.agents["investigator"].ref.key == "anthropic|claude-sonnet-5-5"`.
  - `test_with_ref_copies_provider_and_url`: `with_ref(ModelRef(provider="openai_compat", model="local", base_url="http://x/v1"))`
    gives `.provider == "openai_compat"` and `.base_url == "http://x/v1"`,
    and the original is unchanged.
  - `test_investigator_models_accepts_strings_and_dicts`:
    `["claude-opus-5-5", {"provider": "openrouter", "model": "deepseek/deepseek-v4.1-flash-1017"}]`
    gives keys `["anthropic|claude-opus-5-5", "openrouter|deepseek/deepseek-v4.1-flash-1017"]`.
  - `test_find_model_by_key_and_by_unique_id`, and
    `test_find_model_rejects_ambiguous_and_unknown`: the same id under two
    providers raises a ValueError containing both keys.
  - `test_resolve_model_override_and_stale`: an override chain with one
    allowed entry gives source `override`. An entry that isn't allowed gives
    YAML with `stale=True`. A two-entry chain gives `stale=True`.

  Use the `_repo_config(tmp_path)` pattern from `tests/test_analyst_chain.py`,
  so the real `.env` never leaks in.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_investigator_models.py -q`.
  Expected: FAIL (AttributeError / ImportError).
- [ ] **Step 3: Implement.** Use the interfaces above. Update the
  `settings.example.yaml` comment to show both forms (a string, and an
  `{provider: openrouter, model: …}` dict).
- [ ] **Step 4: Run** the new tests, then the full suite (str call sites
  break here). Then fix `cli.py:250` and `dashboard/app.py` `_model_field`
  to the minimal form that works on `ModelRef`, using `find_model`, and
  returning `ref.key` (Task 5 finishes the UI).
  Expected: green, apart from the known failure.
- [ ] **Step 5: Commit** `feat(config): investigator models are ModelRefs`.

### Task 2: The OpenAI-compatible tool loop

**Files:**
- Create: `src/heim/agent/openai_loop.py`
- Modify: `src/heim/agent/runner.py` (dispatch only, at the top of `run_agent`)
- Modify: `src/heim/tools/base.py` (add `openai_schema()`)
- Test: `tests/test_openai_loop.py` (new)

**Interfaces:**
- Consumes: `AgentCfg.ref` (Task 1); `llm.OPENROUTER_URL`; `config.env`.
- Produces:
  - `Tool.openai_schema() -> dict`, which returns
    `{"type": "function", "function": {"name", "description", "parameters": input_schema()}}`;
  - `endpoint_for(ref: ModelRef) -> tuple[str, str | None]`, which returns
    the URL and key (in `openai_loop.py`, and also used by `llm._complete`,
    which is refactored onto it; that is DRY and its tests stay green);
  - `async run_openai_agent(cfg: AgentCfg, *, system, user_prompt, tools, on_step=None, collect_transcript=False, transport: httpx.AsyncBaseTransport | None = None) -> AgentResult`;
  - in `runner.py`, `run_agent` calls
    `run_openai_agent(...)` when `cfg.provider != "anthropic"` and returns
    its result, closing the tools in the same `finally`.

**Loop rules** (the spec's contract, in the order they apply):
- **Messages:** `[{"role": "system", …}, {"role": "user", …}]`; the body is
  `{model, max_tokens, messages, tools, tool_choice: "auto"}`, plus
  `temperature` when set.
- **Tool calls:** when a reply has `message.tool_calls`, append the assistant
  message as returned. For each call, in order:
  - if the cap is reached, answer with the forced-final text from
    `runner.py` (import it as a constant `FORCED_FINAL_TEXT` and move the
    literal there);
  - else, if `json.loads(arguments)` fails or isn't a dict, answer
    `invalid tool arguments: <error>` with no step recorded;
  - else, if the tool is unknown, answer `unknown tool: <name>`, recorded as
    a step, as the Anthropic loop does;
  - else run it.

  Each answer is a `{"role": "tool", "tool_call_id", "content"}` message.
  The step, `on_step`, first-step credit and transcript entries follow the
  Anthropic loop, with the same shapes: `tool_use` blocks
  `{type, name, input}`.
- **Final answer:** no tool calls means `content or ""` is the output.
  `stop_reason` maps from `finish_reason`: `stop` → `end_turn`,
  `length` → `max_tokens`, anything else is passed through.
- **Usage:** `usage.prompt_tokens` / `usage.completion_tokens`; missing
  counts as 0.
- **Loop end:** the loop runs `hard_step_cap + 3` turns, then returns
  `AgentResult("", …, "loop-cap", True, …)`.
- **Retries:** on `httpx.TransportError`, 429 or ≥500, retry 3 times with a
  `RETRY_WAIT_S * n` sleep (monkeypatchable to 0). Any other status raises
  `RuntimeError(f"HTTP {status}: {body[:200]}")`.

- [ ] **Step 1: Write the failing tests.** Drive them with
  `httpx.MockTransport` returning scripted chat completions, with
  `OPENROUTER_API_KEY` set via monkeypatch and fake `Tool`s that record their
  calls.
  - `test_tool_round_trip_then_answer`: one `tool_calls` turn, then the
    final `## Summary…`. The tool ran once with the parsed args. The second
    request carries `role: tool` with the same `tool_call_id`. `output_text`
    starts with `## Summary`. The tokens are the sum over both turns.
  - `test_bearer_header_and_url`: an OpenRouter ref posts to
    `OPENROUTER_URL` with `Authorization: Bearer <key>`. An `openai_compat`
    ref with no `api_key_env` posts to `base_url + "/chat/completions"`
    with no Authorization header.
  - `test_invalid_json_arguments_answered_not_run` (Review Focus 1).
  - `test_cap_answers_every_call_in_a_turn` (Review Focus 2): with cap=1
    and one turn of 3 calls, exactly 1 tool runs and 3 `tool` messages are
    sent; `forced_final is True`.
  - `test_first_step_carries_turn_usage`: in a turn with 2 calls,
    `on_step` gets `(…, 100, 20)` and then `(…, 0, 0)`.
  - `test_empty_length_reply` (Review Focus 5): the result is `""`,
    `stop_reason == "max_tokens"`.
  - `test_retries_5xx_but_not_400`: 503 then 200 succeeds after 2
    requests. A 400 raises after exactly 1 request, with "HTTP 400" in the
    message.
  - `test_transcript_shape_matches_anthropic_loop`: the transcript entries
    have the roles and block types the replay cassette reads (compare
    against `agent/cassette.py`'s parser by feeding it the transcript).
  - `test_run_agent_dispatches_on_provider`: patch
    `heim.agent.runner.run_openai_agent` and assert it is called for
    `openrouter`, while `AsyncAnthropic` is never constructed.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_openai_loop.py -q`.
  Expected: FAIL (module missing).
- [ ] **Step 3: Implement**, following the rules above.
- [ ] **Step 4: Run** the new tests, then
  `.venv/bin/pytest tests/test_analyst_chain.py tests/test_replay.py tests/test_tool_feedback.py tests/test_observability.py -q`
  (llm refactor + Anthropic path), then the full suite.
  Expected: green.
- [ ] **Step 5: Commit** `feat(agent): OpenAI-compatible tool loop for the investigator`.

### Task 3: Store and queue: provider, `model_pinned`, keyed payloads

**Files:**
- Modify: `src/heim/incidents/store.py` (`_ADDED_COLUMNS["investigations"]`, `_INVESTIGATION_COLS`, a `running_investigations()` helper)
- Modify: `src/heim/pipelines/queue.py` (`payload_for`, `request_from_payload`)
- Modify: `src/heim/pipelines/investigate.py` (`InvestigationRequest`)
- Test: `tests/test_investigator_models.py` (append)

**Interfaces:**
- Produces:
  - columns `investigations.provider TEXT NOT NULL DEFAULT 'anthropic'` and
    `investigations.model_pinned INTEGER NOT NULL DEFAULT 0`;
  - `IncidentStore.running_investigations() -> list[dict]`, the rows with
    status `running`; the daemon reads them before the sweep (Task 4);
  - `InvestigationRequest.model_override: str`, which now holds a **model
    key** or a bare id ("" = not pinned); same field name, so callers
    don't change;
  - `payload_for(..., model="")` stores the key as given;
    `request_from_payload` passes it through unchanged (a bare legacy id
    resolves as Anthropic in Task 4 via `find_model`, or via
    `ModelRef(model=id)` when the id isn't in the allow-list);
  - `request_from_investigation(row)` sets `model_override` **only when
    `row["model_pinned"]`**, to `f"{row['provider']}|{row['model']}"`;
    otherwise "" (the operator's ruling).

- [ ] **Step 1: Write the failing tests**
  - `test_new_columns_migrate_on_old_db`: create the DB with the old schema
    (drop the columns via a fresh connection, or use the existing migration
    test helper pattern), reopen it, and check that `provider` and
    `model_pinned` exist with their defaults.
  - `test_rearm_request_pins_only_pinned_rows`: an unpinned row gives
    `""`; a pinned openrouter row gives
    `"openrouter|deepseek/deepseek-v4.1-flash-1017"`.
  - `test_running_investigations_lists_only_running`.
  - `test_retry_payload_has_no_model`: `enqueue_retry` of a pinned row
    gives `payload["model"] == ""` (spec: retry follows the current choice).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** Add both columns to `_ADDED_COLUMNS` and
  `_INVESTIGATION_COLS`.
- [ ] **Step 4: Run** the new tests, then the full suite. Expected: green.
- [ ] **Step 5: Commit** `feat(store): investigation provider and pinned-model columns`.

### Task 4: Resolve at start, and the failure notice

**Files:**
- Modify: `src/heim/pipelines/investigate.py` (`run_investigation`, approval text, a new `notify_investigation_failed`)
- Modify: `src/heim/daemon.py` (`run_job`, the startup sweep)
- Test: `tests/test_investigator_models.py` (append), using the existing
  `fake_run_agent` rig from `tests/test_tracking.py` (import or copy its
  runtime builder)

**Interfaces:**
- Consumes: `find_model`, `resolve_model`, `INVESTIGATOR_AGENT`,
  `AgentCfg.with_ref` (Task 1); the columns and `running_investigations`
  (Task 3).
- Produces:
  - `effective_investigator(rt, choice: str = "") -> tuple[AgentCfg, bool]`,
    which returns the agent config to run and whether it is pinned.
    `choice` goes through `find_model(choice, allowed)`. When the allow-list
    rejects it but `choice` is a bare id or an anthropic key, the result is
    `ModelRef(provider="anthropic", model=id)`, so legacy and CLI paths
    still work. Any other failure raises `ValueError`. With no choice,
    `resolve_model(yaml_ref, store.model_override("investigator"), allowed)`
    applies, and a stale override logs a WARNING containing
    `"override … ignored"`;
  - `async notify_investigation_failed(rt, *, inv_id: int, host: str, model: str, error: str) -> None`,
    which never raises and sends the Global Constraints text through
    `rt.notify`. `inv_id=0` uses the "Investigation of <host>" wording.
- **Behaviour:**
  1. Before the gate, `run_investigation` calls `effective_investigator`
     to fill the row's `model` and `provider` and the approval text. If
     that raises, it creates the row as `failed` with the reason, notifies
     and returns None.
  2. After approval, inside the `try`, it calls `effective_investigator`
     **again**. Unpinned rows may change model here. When the result
     differs from the row, it updates the row's `model`/`provider`.
     Resolution errors land in the existing `except`.
  3. The `except` block calls `notify_investigation_failed`.
  4. The approval text names the model whenever it isn't the YAML default:
     ` · model: <label>`, plus ` (<provider>)` when the provider isn't
     anthropic.
  5. `run_job`'s `except`, when `seen` has no id, calls
     `notify_investigation_failed(inv_id=0, …)` with the host from the
     payload and the model from the payload, or "default".
  6. At daemon startup, it reads `running_investigations()` **before**
     `sweep_interrupted()`, then notifies each with
     `error="interrupted by daemon restart"`, after the sweep succeeds.

- [ ] **Step 1: Write the failing tests**
  - `test_dashboard_override_used_when_no_pick`: set the override to
    DeepSeek; the fake `run_agent` sees `cfg.provider == "openrouter"`; the
    row has `provider == "openrouter"` and `model_pinned == 0`.
  - `test_pick_beats_override_and_is_pinned`.
  - `test_parked_approval_follows_switch`: create a pending row on Sonnet
    (unpinned), set the override to DeepSeek, then re-arm with approval
    granted via the store. The agent runs on DeepSeek, and the row's model
    is updated.
  - `test_removed_compat_model_fails_and_notifies` (Review Focus 3): a
    pinned `openai_compat` row whose model is no longer offered ends with
    status `failed`, a reason mentioning the model, and one `rt.notify`
    call starting `❌ Investigation #`.
  - `test_agent_exception_notifies_once`: the fake `run_agent` raises
    `RuntimeError("HTTP 400: usage limits")`; the text contains
    `failed on claude-sonnet-5-5: RuntimeError: HTTP 400: usage limits`
    and `/agents/investigator`.
  - `test_error_is_clipped_to_300`.
  - `test_approval_text_names_non_default_model`.
  - `test_job_failure_without_row_notifies` (via `daemon.run_job`, with
    `request_from_payload` patched to raise).
  - `test_restart_sweep_notifies_running_rows`: extract the startup
    sweep into `async def _sweep_and_notify(rt) -> int` in `daemon.py`, and
    test that.
  - `test_dry_run_does_not_notify`: this relies on `rt.notify` being a
    no-op on dry-run; assert no Telegram send.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** behaviour 1–6.
- [ ] **Step 4: Run** the new tests, then `tests/test_durable_approvals.py`,
  `tests/test_jobs.py` and `tests/test_tracking.py`, then the full suite.
  Expected: green.
- [ ] **Step 5: Commit** `feat(investigate): resolve the model at start; Telegram on failure`.

### Task 5: Dashboard: investigator Models panel, dropdown, CLI

**Files:**
- Modify: `src/heim/dashboard/app.py` (`_models_ctx`, the `/actions/models` route, `agent_detail`, `_model_field`, the dropdown context)
- Modify: `src/heim/dashboard/templates/partials/_models_panel.html` (single-slot mode)
- Modify: the dropdown macro in `templates/partials/_macros.html` (~L83): option values become keys, labels `model · provider`
- Modify: `src/heim/dashboard/templates/investigation.html` (the provider next to the model when it isn't anthropic)
- Modify: `src/heim/cli.py` (`--model` validation via `find_model`)
- Test: `tests/test_dashboard_models.py` (append), `tests/test_investigator_models.py` (CLI)

**Interfaces:**
- Consumes: Task 1 helpers; `INVESTIGATOR_AGENT`.
- Produces:
  - `_models_ctx(cfg, override, agent: str = OVERRIDE_AGENT)`. For the
    investigator, it uses `investigator_models`, the YAML ref and
    `single=True`, which renders one slot and the "Model" row label, not
    First/Then;
  - the `/actions/models` form gains a hidden `agent` field, either
    `daily_analyst` (the default, for backward compatibility) or
    `investigator`. Anything else is a 400. For the investigator, exactly
    one slot is required ("Pick one model.");
  - `agent_detail` renders the panel for `key == "investigator"` as well;
  - the dropdown's first option is `default (<effective model label>)`.

- [ ] **Step 1: Write the failing tests**
  - `test_investigator_panel_shows_yaml_default`: `/agents/investigator`
    has `id="h-models"`, `claude-sonnet-5-5` and "default", and exactly one
    `<select`.
  - `test_set_investigator_override`: post `agent=investigator`,
    `slot_1=<deepseek key>` → 303; store `model_override("investigator")`
    chain == [deepseek]. The daily override stays untouched.
  - `test_investigator_rejects_two_models` and
    `test_rejects_unknown_agent` → 400.
  - `test_reset_investigator_override`.
  - `test_dropdown_lists_keys_and_effective_default`: with the override set,
    the incident page's select has the first option text containing
    `deepseek/deepseek-v4.1-flash-1017` and option values that are keys.
  - `test_investigate_action_accepts_key_and_bare_id` (Review Focus 4): both
    give a job whose payload `model` is the key.
  - `test_cli_model_bare_id_still_works`: `heim investigate --model claude-opus-5-5 --dry-run`
    argument validation passes with string `investigator_models`. Test the
    validation function directly, by extracting
    `_cli_model_choice(cfg, value) -> str | None` from `cli.py`.
  - `test_detail_shows_provider_for_openrouter_run`.
  - `test_pending_unpinned_row_shows_current_model`: a `pending_approval`
    unpinned row created on Sonnet, with the override then set to DeepSeek,
    shows "will run on deepseek/deepseek-v4.1-flash-1017" on its detail
    page (spec: the approval card shows the model it will actually use).
    A pinned row shows its own model. The page computes this with
    `resolve_model` (pure, read-only).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_dashboard_models.py`, the existing
  dashboard tests, then the full suite. Expected: green.
- [ ] **Step 5: Commit** `feat(dashboard): choose the investigator's model on /agents/investigator`.

### Task 6: Docs

**Files:** `AGENTS.md`, `README.md` (if it names the investigator as
Anthropic-only), `docs/CONFIGURATION.md`, `docs/DASHBOARD.md`,
`docs/AGENTS-AND-TOOLS.md`, and `config/agents/investigator.yaml` (a
comment showing `provider:` / `base_url:`).

- [ ] **Step 1:** Update the docs per Global Constraints. In AGENTS.md:
  - §5.7 "Multi-model agent loop" becomes ✅ with a 3-line description;
  - the §1 Agent row reads "Anthropic-native or OpenAI-compatible tool
    loop";
  - the §3 OpenRouter row covers the investigator;
  - the test count is updated in both places.
- [ ] **Step 2: Run** the full suite, and
  `grep -rn "Anthropic-only\|Anthropic-native tool loop" AGENTS.md docs README.md`
  for stale claims. Expected: green; no stale claim about the investigator.
- [ ] **Step 3: Commit** `docs: investigator on OpenRouter`.
