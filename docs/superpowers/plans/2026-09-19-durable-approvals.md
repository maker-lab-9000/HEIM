# Durable approvals: queue until the operator reacts

**Goal:** an investigation awaiting approval waits indefinitely — until the operator approves or declines — instead of expiring after `approve_timeout_hours`.

**Spec:** this document. Design system: `docs/design/dashboard-ui.md`.

## Why removing the timeout is not enough

Three independent mechanisms currently end a pending approval. Fixing only the timeout produces something *worse* than today — an approval that survives until the next restart, then dies silently behind a Telegram message whose buttons no longer do anything.

1. **The timeout** — `approvals.approve_timeout_hours: 6`; on expiry the investigation is `declined` with `approval_decision='timeout'` and the incident is re-proposed on the next run.
2. **Restart wipes it** — `store.sweep_interrupted()` marks every `running` *and* `pending_approval` investigation `failed` on daemon start (`src/heim/incidents/store.py:860-880`). Every deploy or crash silently kills all parked approvals.
3. **The buttons are ephemeral** — `callback_data` is `heim:<random-uid>:y|n` where the uid keys an **in-memory asyncio future** (`src/heim/channels/telegram.py:93-94`). After a restart, the old message's buttons resolve nothing: the operator taps Approve and gets silence.

## The design

### A. Indefinite is a first-class setting

`approvals.approve_timeout_hours: 0` means *wait forever*; any positive value keeps today's behaviour. Ship **0 as the default** (the operator asked for this) and say so in both settings yamls. `outcome_timeout_hours` gains the same `0` semantics but keeps its 8h default — an unanswered *outcome* prompt is benign (the incident stays flagged), whereas an unanswered *approval* currently loses the investigation.

The wait must not burn a CPU: the store-decision poller keeps its interval; only the deadline becomes optional.

### B. Buttons carry the investigation id, not a memory address

Change `callback_data` to `heim:inv:<investigation_id>:<y|n>` for approvals and `heim:out:<investigation_id>:<y|n>` for outcome confirms. The Telegram update consumer resolves them by **writing to the store** (`set_approval_decision` / the outcome equivalent), not by completing an in-memory future. The waiting coroutine already polls `approval_decision` (`_store_decision`), so it picks the answer up within one poll interval — and so does a *re-armed* waiter after a restart.

Consequences to handle:
- The consumer must run whenever the daemon is up, not only while an `ask()` is outstanding, or a tap during a restart window is lost. Start it with the daemon.
- A tap for an investigation that is no longer pending (already decided, or gone) must be acknowledged and ignored, with the button feedback saying so rather than failing silently.
- Keep the existing in-memory path working for the *same-process* case so behaviour is unchanged when nothing restarted; the store write is the source of truth either way. Do not end up with two competing resolutions of the same tap — the store decision wins, and the in-memory future is cancelled when it does.

### C. Restart re-arms instead of failing

- `sweep_interrupted()` stops touching `pending_approval` rows. It still fails `running` ones (those genuinely cannot resume — their agent loop is gone) and still interrupts `running` jobs. Update its docstring: the sweep now distinguishes *mid-flight* from *parked*.
- On daemon start, after the sweep, re-arm every `pending_approval` investigation: resume waiting on its store decision, with the configured timeout (or none). Do **not** re-send the Telegram prompt — the original message's buttons now work again because they carry the investigation id. Log one line naming how many were re-armed.
- A re-armed approval must still acquire the concurrency semaphore only *after* it is approved, exactly as today, so parked approvals never consume execution slots.

### D. Visibility

The dashboard already counts `pending approval` on the overview and lists them. Add, on the investigation detail page of a `pending_approval` row, how long it has been waiting (`waiting 3h 12m`) next to the status — an approval that waits forever should show its age, or a forgotten one is invisible.

## Tests

- `approve_timeout_hours: 0` → the waiter does not expire (drive the clock well past the old deadline and assert it is still pending and still waiting).
- A positive value still expires exactly as before (the existing behaviour must not regress).
- `sweep_interrupted` leaves `pending_approval` untouched while still failing `running` — assert both in one test so the distinction is pinned.
- Restart re-arm: create a pending approval, simulate a restart (fresh runtime over the same store), assert a waiter is re-armed and that a store decision written afterwards resolves it.
- A Telegram tap resolves an approval **through the store**: given `callback_data = heim:inv:<id>:y`, the consumer writes `approval_decision='approve'` for that id — and a waiter in a *different* process (i.e. one that never created the button) sees it.
- A tap for an already-decided or unknown investigation is acknowledged, changes nothing, and reports that it is no longer pending.
- Detail page shows the waiting age for a pending row, and does not for a decided one.
