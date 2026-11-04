# Daily analyst provider chain + dashboard model switch — design

Date: 2026-11-04 · Status: draft for approval · Scope: project 1 of 2

## Why

The Anthropic workspace hit its API usage limit and the daily report was simply
not produced:

```
Monitoring gap: daily analysis failed: BadRequestError: Error code: 400 —
'You have reached your specified workspace API usage limits …'
```

Raising the limit is not an option for the operator. The daily analyst today
has a fixed two-step `primary` / `fallback` (OpenRouter free Gemma → Anthropic
Opus); both failed, and the only trace was a Telegram line and a dashboard
monitoring-gap row. The operator wants:

- a provider **order** of their choosing — **Anthropic first, OpenRouter
  (`deepseek/deepseek-v4.1-flash-1017`) as fallback**, and **later a local
  llama.cpp server as last resort**;
- to switch models/order **from the dashboard**, without editing YAML or
  restarting;
- an **email** when every provider fails, not only a Telegram line.

Only the daily report was missed during the outage, so this project covers the
daily analyst only.

## Goals

1. The daily analyst runs through an **ordered chain** of 1..N model entries and
   uses the first that answers usably.
2. The chain is set in YAML (the default) and can be **overridden from the
   dashboard**, effective from the next run, no restart.
3. When the answer came from anything but the first entry, that is **visible**
   (dashboard + Telegram), so an Anthropic outage cannot hide behind a working
   report.
4. When **every** entry fails, the operator gets an **email** (plus the existing
   Telegram line), naming each entry and why it failed.
5. The config shape leaves room for llama.cpp as a later chain entry with no new
   code (it speaks the same OpenAI-compatible chat API as OpenRouter).

## Non-goals

- **Project 2** — an OpenAI-compatible *tool-calling* loop so the investigator
  and security auditor can fall back off Anthropic. Separate design later.
  Until then those two agents stay Anthropic-only and are not touched here.
- Actually deploying/configuring llama.cpp (later; this project only must not
  block it).
- OpenAI (the company/API) as a provider. "OpenAI-compatible" below means the
  wire format OpenRouter and llama.cpp share, nothing more.
- Free-text model entry in the dashboard.

## Anti-goals (would be a failure even if it "works")

- A fallback silently answering for days while Anthropic is down and nobody
  notices.
- An "all providers failed" email that only shows the last error.
- The dashboard becoming a pipeline writer beyond one new, allow-listed table.
- A model selectable in the dashboard that has no price → runs that look free.
  (Unpriced still renders "—" as today; see allow-list below.)
- Breaking existing `daily_analyst.yaml` files that still use
  `primary` / `fallback`.

## Constraints from the repo

- `src/heim/llm.py` is a **ported (golden) module** (docstring: n8n PAM 10
  "Basic LLM Chain: primary model + automatic fallback"). Generalising
  primary+fallback to a chain is a *deliberate* behaviour change: update its
  docstring with a dated note and update/add the tests, per AGENTS.md §2.
- `reports/daily_dashboard.py` (the daily email renderer) is golden too. This
  design does **not** edit it (see "Visibility").
- Dashboard writes go only through `_ACTION_HELPERS` in `dashboard/app.py`; the
  daemon is the only executor. The new override table is the only new write
  surface.
- Fire-and-forget side channels: the failure email and Telegram lines must
  never raise out of the failure path (log and swallow), so the original
  analyst failure is what the daemon wrapper records.
- `.venv/bin/pytest -q` stays green; deployment identity (llama.cpp URL, keys)
  comes from `.env` via `${VAR}`.

## Design

### 1. Config: a chain

`config/agents/daily_analyst.yaml` gains `chain:` — an ordered list of
`ModelRef`:

```yaml
kind: analyst
name: daily_analyst
chain:
  - provider: anthropic
    model: claude-opus-5-5
  - provider: openrouter
    model: deepseek/deepseek-v4.1-flash-1017
  # later, last resort:
  # - provider: openai_compat
  #   model: local
  #   base_url: ${HEIM_LLAMACPP_URL:-}
max_tokens: 8192
prompt: analyst.md
```

- `ModelRef.provider` becomes `anthropic | openrouter | openai_compat`.
  `openai_compat` takes `base_url` (required for it) and optional
  `api_key_env` (name of the env var holding a key; none = no auth header,
  which is what a LAN llama.cpp needs). `openrouter` is kept as the named
  shortcut for `openai_compat` at the OpenRouter URL with `OPENROUTER_API_KEY`.
- **Back-compat:** if `chain` is absent, `primary` (+ `fallback` if present)
  becomes the chain `[primary, fallback]`. Specifying both `chain` and
  `primary` is a config error at load. An empty chain is a config error.
- Shipped default in the committed YAML: Anthropic Opus 5.5 → OpenRouter
  DeepSeek Flash, as above.
- Per-entry `max_tokens` is not added; the analyst-level `max_tokens` applies to
  every entry (builder may revisit if DeepSeek rejects 8192).

### 2. Running the chain

`llm.analyst_complete(cfg, system, user, chain=None)` walks the chain in order
(the `chain` argument is the effective chain from §4; default = the config's):

- An entry **fails** when the call raises (HTTP error, timeout, empty content,
  missing key) **or** — *new, my call* — when its text does not parse as the
  analyst JSON (`parse_analysis` returns `None`). Today an unparseable reply ends
  the run with no report; with a chain, a garbled answer from one model should
  let the next one try. This costs a second call only in that case.
- On success it returns the text, the model that answered, usage, and the list
  of **attempts** (`[{provider, model, ok, error}]`, error text clipped to ~300
  chars) so the caller can record and surface them.
- When every entry fails it raises a dedicated `AnalystChainFailed` carrying
  all attempts; its `str()` lists every entry and its error in order (this is
  what the daemon's existing `_exc_text` → `agent_runs.error` → dashboard
  "Monitoring gap" line will show; the 200-char clip in `_exc_text` should be
  raised enough to fit a 3-entry chain, or the gap line should read the
  attempts — builder's call).
- Cost is still priced against the model that answered (unchanged behaviour).
  Tokens spent on failed attempts that did return usage (e.g. an unparseable
  reply) are added to the run's tokens/cost — *my call*, because they were
  billed.

### 3. Failure email + Telegram

When `AnalystChainFailed` reaches `run_daily`:

- send a short **email** — subject like `HEIM daily report NOT produced —
  all analyst models failed` — listing each attempt (provider, model, error)
  and the run time, plus a line that metrics were collected fine and the next
  scheduled run will retry. Plain, small HTML built in a new non-golden helper
  (not `reports/daily_dashboard.py`).
- keep the existing Telegram line from the daemon wrapper, now carrying every
  attempt rather than one exception.
- both are fire-and-forget; then re-raise so the daemon records the failed
  heartbeat as today.
- dry-run: the email goes to `out/` like every other email.
- Applies to the CLI `heim daily` too (the email lives in the pipeline, not the
  daemon wrapper).

### 4. Dashboard override

- **Allow-list** in settings: `analyst_models: list[ModelRef]` — the entries
  the dashboard may offer. Empty = the dashboard shows the chain read-only with
  no form. Like `investigator_models`, every entry should have a
  `model_prices` row; an unpriced one is still allowed but the form marks it
  "unpriced".
- **Storage:** new table `model_overrides(agent TEXT PRIMARY KEY, chain_json
  TEXT, updated_at TEXT, updated_by TEXT)`. Rows for agent `daily_analyst` only
  for now (the key leaves room for project 2). Store helpers
  `set_model_override` / `clear_model_override`, both added to
  `_ACTION_HELPERS`.
- **Effective chain** at the start of each daily run = the override if present
  and every entry is still in `analyst_models`; otherwise the YAML chain (a
  stale override — an entry removed from the allow-list — is ignored with a
  WARNING and the page says so). The daemon reads it per run; no restart.
- **Persistence:** the override stays until the operator resets it (no expiry).
- **UI:** on `/agents/daily` (the daily analyst's agent page), a "Models" panel:
  the effective chain as an ordered list, marked "default (YAML)" or
  "override — set <time>"; a form to pick 1..N entries from the allow-list in
  order (an ordered set of selects is fine; no drag-and-drop needed) plus
  **Reset to default**. Real `<form method="post">` under `/actions/`
  enhanced by htmx, like the other actions. Follow `design.md`; read it before
  touching templates.
- `heim` CLI parity is nice-to-have, not required (builder's call).

### 5. Visibility of fallbacks

**"Fallback" means: the answer came from anything but the first entry of the
chain *in effect for that run*** (the override if one is active, else YAML) —
decided by the operator. An active override is **not** itself flagged anywhere
beyond the "override — set <time>" note on `/agents/daily`: no overview note,
no Telegram reminder, no email line. The operator chose it and reads the
daily report.

- `runs` gains `attempts_json` (the attempts list). `model_used` keeps meaning
  "the model that answered".
- Dashboard: the overview's latest-run line and the findings run headers
  already show `model_used`; on a fallback run, append "fallback" with the
  failed entries' reasons in a tooltip/expander, and the daily agent's status
  reads **degraded** (not healthy) for that run. Today the daily agent's status
  comes only from the ok/fail `agent_runs` heartbeat, so the daemon's daily
  wrapper records the fallback in the heartbeat's `detail_json` (e.g.
  `fallback: true` + failed entries) and `agents.py` maps an ok-but-fallback run
  to degraded.
- Telegram: one line on a fallback run, e.g. `⚠️ HEIM daily: Anthropic
  claude-opus-5-5 failed (usage limit…); report by
  deepseek/deepseek-v4.1-flash-1017`.
- **Daily email** (operator decided: yes): on a fallback run, the subject gets a
  tag — e.g. `[fallback: deepseek-v4.1-flash-1017]` — and a short banner line is
  prepended to the HTML naming the model that answered and each failed entry
  with its reason. Both are done in `pipelines/daily.py` around the
  `daily_email(...)` result; the golden `reports/daily_dashboard.py` is **not**
  edited. Non-fallback runs: email unchanged.

## Left to the builder

- Exact module split (chain runner in `llm.py` vs a new module that `llm.py`
  calls), naming, migration mechanics for the two new columns/table (follow
  how `store.py` adds columns today).
- Timeouts per provider (OpenRouter today: 180 s) and whether to retry a
  transient error once before moving down the chain.
- Exact dashboard markup within `design.md`.
- Test shape; at minimum: chain order, fall-through on error and on unparseable
  output, all-fail raises with every attempt, back-compat `primary/fallback`
  load, stale-override fallback to YAML, the allow-list validation on the POST
  route, the failure email in dry-run.

## Calls made without the operator (check these)

- Unparseable output counts as a failed attempt and moves down the chain.
- Tokens of failed-but-billed attempts are added to the run's cost.
- Fallback-answered runs mark the daily agent **degraded**.
- A failed run (every entry failed) writes no `runs` row, as today; the failure
  lives in the heartbeat and the failure email.
- Overrides never expire; a stale override silently (WARNING + page note)
  falls back to the YAML chain rather than blocking the run.
- The failure email is a new small template, not the dashboard email.
