# Investigator on OpenRouter + dashboard model choice — design

Date: 2026-11-04 · Status: draft for approval · Scope: project 2 of 2 (follows
`2026-11-04-analyst-provider-chain-design.md`, built on its branch)

## Why

The Anthropic workspace hit its API usage limit. Project 1 made the daily
analyst fall back to OpenRouter DeepSeek. The investigator still runs only
on Anthropic (`agent/runner.py` uses Anthropic-native tool calling), so
during an outage every investigation fails, and nothing tells the operator.

The operator wants to:

- run investigations on an OpenRouter model, starting with
  `deepseek/deepseek-v4.1-flash-1017`;
- choose the investigator's model **from the dashboard**, as they now can for
  the analyst;
- get a **Telegram message when an investigation fails**, so they know to
  switch models.

## Goals

1. The investigator can run on Anthropic, OpenRouter, or any OpenAI-compatible
   server (later a local llama.cpp), using the same tools, guards, approval
   gate, step cap, tracking, pricing and delivery as today.
2. **One model at a time, chosen by the operator.** The default comes from
   `config/agents/investigator.yaml`. The dashboard can override it from the
   next investigation on, with no restart.
3. The Investigate button's per-run dropdown can also pick an OpenRouter
   model.
4. A failed investigation sends one Telegram line saying what failed, the
   model it failed on, and where to change the model.

## Non-goals

- **No automatic fallback** for the investigator: the operator's decision.
  The model changes only when the operator picks one. An investigation that
  fails on Anthropic's limit fails and notifies; it does not retry on
  DeepSeek.
- The weekly security auditor stays on Anthropic, untouched.
- `heim replay` stays Anthropic-only. Making it run an OpenRouter model is
  a later step; the cassette design does not block it.
- No change to prompts, the report contract (`## Summary` + salvage), the
  tools or their guards.

## Anti-goals

- An OpenRouter investigation must not get **more** power than an Anthropic
  one: same tool list, same guards, same hard step cap, same approval.
- A model the operator did not offer in settings must never be runnable from
  the dashboard (an allow-list, like `analyst_models`).
- An investigation must never show "complete" with an empty or garbage
  report. A weak model that gives up is marked `incomplete` by the existing
  salvage, with its raw output kept.

## What the operator sees

- **`/agents/investigator`** gets a **Models** panel, the same component as
  the daily one but with **one** select:
  - **Source:** default (`config/agents/investigator.yaml`), override · set
    time, or "override ignored" when the stored model is no longer offered.
  - **Model:** shown with its provider, and "unpriced" when it has no
    `model_prices` row.
  - **Save** and **Reset to default** buttons. With an empty allow-list the
    panel is read-only and says which setting to fill in, as the daily one
    does.
- **The Investigate dropdown** (host cards, incidents): its options come from
  the same allow-list and show provider and model. The first option stays
  "default (<effective model>)", where the effective model is the dashboard
  override if set, otherwise the YAML.
- **Investigation detail and list:** the model column is unchanged. The
  provider shows next to the model when it is not Anthropic.
- **The approval prompt** (Telegram + dashboard) names the model whenever it is
  not the YAML default (today it only names a per-run choice), so the operator
  approving an investigation knows it will run on DeepSeek.
- **Telegram, on failure:**
  `❌ Investigation #42 (ubuntu-server) failed on claude-sonnet-5-5: BadRequestError: … usage limits … — change the model on /agents/investigator`.
  The error is clipped to about 300 characters.

## How it works (decided)

### Model identity

The analyst's `ModelRef` (`provider`, `model`, `base_url`, `api_key_env`,
`.key`) is the single way to name a model.

- `AgentCfg` gains `provider` (default `anthropic`), `base_url` and
  `api_key_env`, plus a `ref` property returning its `ModelRef`. Existing
  agent YAMLs load unchanged.
- `settings.investigator_models` changes from `list[str]` to
  `list[ModelRef]`. **Plain strings are still accepted** and mean
  `{provider: anthropic, model: <string>}`, so a live `settings.yaml` with
  `investigator_models: [claude-opus-5-5]` keeps working.

### Which model a run uses

Highest first:

1. An **explicit per-run pick**: the dropdown or `heim investigate --model`.
2. The dashboard override (`model_overrides` row with
   `agent="investigator"` and a one-entry chain).
3. `config/agents/investigator.yaml`.

An override whose key is no longer in `investigator_models` is ignored
("stale"), exactly as for the analyst: it is logged as a WARNING and labelled
on the panel.

**Retries and approvals that were waiting use the current choice** (operator's
ruling). The model is resolved **when the agent starts**, after the approval
gate, not when the row is created:

- **Retry** carries no model of its own. It runs on whatever 2–3 resolve to
  at that moment, as `enqueue_retry` does today.
- **A parked approval**, whether re-armed after a restart or just approved
  late, runs on the model that 2–3 resolve to when it is approved. If that
  differs from the one recorded when it was proposed, the row's
  `model`/`provider` are updated at start. The old Telegram prompt may then
  name a stale model; that is accepted. The dashboard's approval card shows
  the model it will actually use.
- *(My call.)* An explicit per-run pick (1) **is** the current choice for
  its run, so it stays pinned through approval and re-arm. A row records
  whether its model was picked (`model_pinned`, 0/1). Only unpinned rows
  follow the setting.

### Persistence

- `investigations` gains a `provider` column (TEXT, default `'anthropic'`),
  next to the existing `model`.
- `investigations` also gains `model_pinned` (INTEGER, default 0).
- A pinned row being re-armed rebuilds its `ModelRef` from `provider` +
  `model`. It looks up `base_url` and `api_key_env` from the allow-list or
  the YAML entry with the same provider and model. If no entry matches (an
  `openai_compat` model that was removed), the run fails with a clear reason
  and the Telegram line goes out, rather than guessing a URL.
- The queue payload carries the model key instead of a bare model id.
  Payloads already queued with a bare id still load as Anthropic.
- *(Builder check; my call.)* `heim investigate --model` and the dashboard's
  `model` form field accept either a full key (`provider|model[|base_url]`)
  or a bare model id. A bare id is accepted only when exactly one
  `investigator_models` entry has it, and is otherwise rejected with the
  matching keys listed. Today's `--model claude-opus-5-5` keeps working.
  The dropdown always submits the full key.

### The tool loop

`run_agent(cfg, …)` keeps its signature and `AgentResult`, and dispatches on
`cfg.provider`:

- **`anthropic`:** today's loop, byte-for-byte unchanged.
- **`openrouter` / `openai_compat`:** a new loop over the OpenAI-compatible
  chat API (`POST {base}/chat/completions` with `tools`, `tool_choice: auto`)
  with the **same contract**:
  - the same `hard_step_cap` (plus 3 turns of slack), the same forced-final
    message, the same `on_step(seq, tool, args, result, duration_ms, turn_in,
    turn_out)` with first-step-of-turn token attribution, and the same
    transcript shape (plain dicts with text, tool_use and tool_result), so
    the stored transcript and the dashboard keep working;
  - tool schemas are built from the same tool YAML
    (`{"type": "function", "function": {name, description, parameters}}`);
  - tool calls whose `arguments` JSON can't be parsed are answered with an
    error tool result, as an unknown tool is today; they are never executed
    with guessed arguments;
  - usage comes from `usage.prompt_tokens` / `completion_tokens`, and pricing
    from `model_prices[model]` as today;
  - the URL and key come from the same rules as `llm._complete`: OpenRouter
    uses `OPENROUTER_API_KEY`; `openai_compat` uses `base_url` and an optional
    `api_key_env`. Retries match the Anthropic loop (3 attempts, 3 s × n
    backoff) for connection errors and 5xx/429 only. A 4xx error fails at
    once.
  - `stop_reason` maps from `finish_reason`: `stop` → `end_turn`,
    `length` → `max_tokens`.
- The security auditor also calls `run_agent`. Its YAML is Anthropic, so it
  keeps taking the unchanged path.

### Failure notification

One helper (e.g. `notify_investigation_failed(rt, inv_id, host, model, error)`)
sends the Telegram line above. It is fire-and-forget (its own failures are
logged), and is skipped on `--dry-run` and when no Telegram is configured.
*(Builder check; my call.)* It is called from every place an investigation
or its job becomes `failed`:

- `run_investigation`'s `except` block;
- model resolution, which moves inside that `try`, so an unresolvable model
  marks the row failed and notifies instead of raising past it;
- the restart sweep, for each mid-flight investigation it fails, worded
  "interrupted by a restart";
- the queue worker, for a job that fails before any investigation row
  exists. The line then names the host, not an id.

One line per failed investigation (or row-less job), from any trigger.

### Dashboard writes

The panel posts to the existing `POST /actions/models` route with an
`agent=investigator` field, or to its sibling route; the builder picks
whichever is cleaner. Writes go only through the existing
`set_model_override` / `clear_model_override` helpers, both already in
`_ACTION_HELPERS`. The analyst panel's validation rules apply, with
"exactly one model" in place of "an ordered list".

## Constraints

- AGENTS.md invariants hold, read-only agent (4) in particular. The report
  contract (6) holds for both loops.
- `agent/runner.py` names no n8n node, so it isn't golden, but its Anthropic
  path keeps its existing tests green unmodified.
- The dashboard follows `design.md`: lamps and words, no emoji in the UI.
  (The Telegram line may carry ❌, as existing Telegram lines do.)
- Secrets stay in `.env`; no URL or key in git.
- Tests do not touch the network: the new loop is tested against a fake
  transport (`httpx.MockTransport`).

## Left to the builder

- Whether the new loop lives in `runner.py` or a sibling module (e.g.
  `agent/openai_loop.py`).
- The panel template: reuse `_models_panel.html` with a single-slot mode, or a
  small sibling partial.
- Exact wording of panel messages, within `design.md`.

## Calls made without the operator (check these)

- **The per-run dropdown wins over the dashboard override**, and a pinned
  pick survives re-arm. The dropdown is the more specific choice.
- **Plain-string `investigator_models` entries stay valid as Anthropic.** This
  avoids breaking the live `settings.yaml`.
- **One allow-list for both the panel and the dropdown**, namely
  `investigator_models`, separate from `analyst_models`. The two agents may
  reasonably offer different models: Haiku is cheap enough for the analyst
  but weak for tool use.
- **Telegram on every failed investigation**, not only on provider errors. A
  crash for any other reason is just as invisible today.
- **No retry on 4xx.** A usage-limit 400 retried three times wastes about
  18 s and changes nothing (the Anthropic path still does this. Unchanged,
  out of scope).
